/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "fast-lsa-commands.hpp"

#include <ndn-cxx/mgmt/control-parameters.hpp>

namespace nlsr::update {

FastLsaCommandProcessor::FastLsaCommandProcessor(ndn::mgmt::Dispatcher& dispatcher,
                                                 Lsdb& lsdb,
                                                 ConfParameter& confParam)
  : CommandManagerBase(dispatcher)
  , m_lsdb(lsdb)
  , m_confParam(confParam)
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
  // Expected parameters encoded in Name/Parameters:
  // - Name: Prefix (required)
  // - ExpirationPeriod: LifetimeMs (optional)
  // - FaceId: NeighborFaceId (optional)
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

  std::optional<ndn::Name> neighborRouterName;
  // NeighborFaceId is optional; mapping FaceId->NeighborName 可在阶段二完善

  auto now = ndn::time::system_clock::now();
  auto lsa = std::make_shared<FastPrefixLsa>(m_confParam.getRouterPrefix(), ++m_fastSeq,
                                             now + lifetime, prefixes,
                                             neighborRouterName, newFaceSeq);

  m_lsdb.installLsa(lsa);

  context.append(ndn::Block());
  context.end();
}

} // namespace nlsr::update


