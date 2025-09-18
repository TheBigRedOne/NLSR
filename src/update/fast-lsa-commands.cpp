/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "fast-lsa-commands.hpp"

#include <ndn-cxx/mgmt/control-parameters.hpp>

namespace nlsr::update {

FastLsaCommandProcessor::FastLsaCommandProcessor(ndn::mgmt::Dispatcher& dispatcher,
                                                 Lsdb& lsdb,
                                                 ConfParameter& confParam,
                                                 ndn::nfd::Controller& controller)
  : CommandManagerBase(dispatcher)
  , m_lsdb(lsdb)
  , m_confParam(confParam)
  , m_controller(controller)
{
  registerCommands();
}

ndn::mgmt::Authorization
FastLsaCommandProcessor::makeAuthorization()
{
  return [] (const ndn::Name& prefix, const ndn::Interest& interest,
             const ndn::mgmt::ControlParameters* params, const ndn::mgmt::CommandContinuation& cont) {
    // Localhost-only
    cont(ndn::mgmt::makeSuccess());
  };
}

void
FastLsaCommandProcessor::registerCommands()
{
  auto auth = makeAuthorization();
  m_dispatcher.addControlCommandHandler(
    ndn::Name("/localhost/nlsr/fast-lsa/trigger"),
    auth,
    [this] (const auto& p, const auto& i, auto& c) { handleTrigger(p, i, c); });
}

void
FastLsaCommandProcessor::handleTrigger(const ndn::mgmt::ControlParameters& params,
                                       const ndn::Interest& interest,
                                       ndn::mgmt::StatusDatasetContext& context)
{
  // Expected parameters encoded in ControlParameters:
  // - Name: Prefix (required)
  // - ExpirationPeriod: LifetimeMs (optional, default 1000ms)
  // - FaceId: NeighborFaceId (optional, preferred)
  // - Cost: NewFaceSeq (optional)

  std::vector<ndn::Name> prefixes;
  if (params.hasName()) {
    prefixes.push_back(params.getName());
  }
  else {
    context.reject(400, "Missing Prefix name");
    return;
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
    context.append(ndn::Block()); context.end(); return;
  }
  m_lastTriggerTime[prefixes.front()] = nowSteady;

  // De-dup by NewFaceSeq when provided: ignore if not newer
  if (newFaceSeq) {
    auto itSeq = m_lastSeqByPrefix.find(prefixes.front());
    if (itSeq != m_lastSeqByPrefix.end() && itSeq->second >= *newFaceSeq) {
      context.append(ndn::Block()); context.end(); return;
    }
    m_lastSeqByPrefix[prefixes.front()] = *newFaceSeq;
  }

  auto now = ndn::time::system_clock::now();
  // Attempt to register short-lived FIB via RIB if FaceId provided
  if (params.hasFaceId()) {
    ndn::nfd::ControlParameters ribParams;
    ribParams.setName(prefixes.front())
             .setFaceId(params.getFaceId())
             .setExpirationPeriod(lifetime);
    // best-effort; errors ignored
    try { NfdRibCommandProcessor::registerRoute(m_controller, ribParams); }
    catch (...) {}

    // Schedule active unregister at expiration
    try {
      auto unregisterParams = ndn::nfd::ControlParameters().setName(prefixes.front())
                                                              .setFaceId(params.getFaceId());
      m_lsdb.m_scheduler.schedule(lifetime, [this, unregisterParams] {
        try { NfdRibCommandProcessor::unregisterRoute(m_controller, unregisterParams); }
        catch (...) {}
      });
    }
    catch (...) {}
  }

  auto lsa = std::make_shared<FastPrefixLsa>(m_confParam.getRouterPrefix(), ++m_fastSeq,
                                             now + lifetime, prefixes,
                                             std::nullopt, newFaceSeq);

  m_lsdb.installLsa(lsa);

  context.append(ndn::Block());
  context.end();
}

} // namespace nlsr::update


