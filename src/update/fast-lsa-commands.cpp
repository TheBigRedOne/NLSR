/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "fast-lsa-commands.hpp"
#include "nfd-rib-command-processor.hpp"
#include <functional>

#include <ndn-cxx/mgmt/control-parameters.hpp>

namespace nlsr::update {

FastLsaCommandProcessor::FastLsaCommandProcessor(ndn::mgmt::Dispatcher& dispatcher,
                                                 Lsdb& lsdb,
                                                 ConfParameter& confParam,
                                                 ndn::nfd::Controller& controller)
  : ManagerBase(dispatcher, "fast-lsa")
  , m_lsdb(lsdb)
  , m_confParam(confParam)
  , m_controller(controller)
{
  registerCommands();
}

void
FastLsaCommandProcessor::registerCommands()
{
  m_dispatcher.addControlCommand<ndn::nfd::ControlParameters>(
    makeRelPrefix("trigger"),
    ndn::mgmt::makeAcceptAllAuthorization(),
    [] (const ndn::mgmt::ControlParameters&) { return true; },
    std::bind(&FastLsaCommandProcessor::handleTrigger, this,
              std::placeholders::_1,
              std::placeholders::_2,
              std::placeholders::_3,
              std::placeholders::_4));
}

void
FastLsaCommandProcessor::handleTrigger(const ndn::Name& prefix,
                                       const ndn::Interest& interest,
                                       const ndn::mgmt::ControlParameters& parameters,
                                       const ndn::mgmt::CommandContinuation& done)
{
  // Expected parameters encoded in ControlParameters:
  // - Name: Prefix (required)
  // - ExpirationPeriod: LifetimeMs (optional, default 1000ms)
  // - FaceId: NeighborFaceId (optional, preferred)
  // - Cost: NewFaceSeq (optional)

  const auto& params = static_cast<const ndn::nfd::ControlParameters&>(parameters);

  std::vector<ndn::Name> prefixes;
  if (params.hasName()) {
    prefixes.push_back(params.getName());
  }
  else if (!prefix.empty()) {
    prefixes.push_back(prefix);
  }
  else {
    ndn::nfd::ControlResponse resp; resp.setCode(400).setText("Missing Prefix name");
    return done(resp);
  }

  ndn::time::milliseconds lifetime = 1000_ms;
  if (params.hasExpirationPeriod()) {
    lifetime = params.getExpirationPeriod();
  }

  std::optional<uint32_t> newFaceSeq;
  if (params.hasCost()) {
    newFaceSeq = static_cast<uint32_t>(params.getCost());
  }

  // Throttle per prefix (simple): 1 trigger / 500ms
  auto nowSteady = ndn::time::steady_clock::now();
  auto itLast = m_lastTriggerTime.find(prefixes.front());
  if (itLast != m_lastTriggerTime.end() && (nowSteady - itLast->second) < 500_ms) {
    ndn::nfd::ControlResponse resp; resp.setCode(202).setText("throttled");
    return done(resp);
  }
  m_lastTriggerTime[prefixes.front()] = nowSteady;

  // De-dup by NewFaceSeq when provided: ignore if not newer
  if (newFaceSeq) {
    auto itSeq = m_lastSeqByPrefix.find(prefixes.front());
    if (itSeq != m_lastSeqByPrefix.end() && itSeq->second >= *newFaceSeq) {
      ndn::nfd::ControlResponse resp; resp.setCode(202).setText("dedup");
      return done(resp);
    }
    m_lastSeqByPrefix[prefixes.front()] = *newFaceSeq;
  }

  auto now = ndn::time::system_clock::now();
  // Attempt to register short-lived FIB via RIB if FaceId provided
  if (params.hasFaceId()) {
    ndn::nfd::ControlParameters ribParams;
    ribParams.setName(prefixes.front())
             .setFaceId(params.getFaceId())
             .setOrigin(ndn::nfd::ROUTE_ORIGIN_OPTOFLOOD)
             .setExpirationPeriod(lifetime);
    // best-effort; errors ignored
    try { update::NfdRibCommandProcessor::registerRoute(m_controller, ribParams); }
    catch (...) {}

    // Schedule active unregister at expiration
    try {
      ndn::nfd::ControlParameters unregisterParams;
      unregisterParams.setName(prefixes.front())
                     .setFaceId(params.getFaceId())
                     .setOrigin(ndn::nfd::ROUTE_ORIGIN_OPTOFLOOD);
      m_lsdb.schedule(lifetime, [this, unregisterParams] {
        try { NfdRibCommandProcessor::unregisterRoute(m_controller, unregisterParams); }
        catch (...) {}
      });
    }
    catch (...) {}
  }

  auto lsa = std::make_shared<FastPrefixLsa>(m_confParam.getRouterPrefix(), ++m_fastSeq,
                                             now + lifetime, prefixes,
                                             std::nullopt, newFaceSeq);

  m_lsdb.installLsaPublic(lsa);
  ndn::nfd::ControlResponse resp; resp.setCode(200).setText("OK");
  done(resp);
}

} // namespace nlsr::update


