/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef NLSR_UPDATE_FAST_LSA_COMMANDS_HPP
#define NLSR_UPDATE_FAST_LSA_COMMANDS_HPP

#include "manager-base.hpp"
#include "../lsdb.hpp"
#include "../lsa/fast-prefix-lsa.hpp"
#include "../conf-parameter.hpp"
#include "nfd-rib-commands.hpp"

#include <ndn-cxx/mgmt/dispatcher.hpp>

namespace nlsr::update {

class FastLsaCommandProcessor : public CommandManagerBase
{
public:
  FastLsaCommandProcessor(ndn::mgmt::Dispatcher& dispatcher,
                          Lsdb& lsdb,
                          ConfParameter& confParam);

private:
  void
  registerCommands();

  ndn::mgmt::Authorization
  makeAuthorization();

  void
  handleTrigger(const ndn::mgmt::ControlParameters& params,
                const ndn::Interest& interest,
                ndn::mgmt::StatusDatasetContext& context);

private:
  Lsdb& m_lsdb;
  ConfParameter& m_confParam;
  uint64_t m_fastSeq = 0;
  // simple de-dup and throttle
  std::unordered_map<ndn::Name, uint64_t, std::hash<ndn::Name>> m_lastSeqByPrefix;
  std::unordered_map<ndn::Name, ndn::time::steady_clock::time_point, std::hash<ndn::Name>> m_lastTriggerTime;
};

} // namespace nlsr::update

#endif // NLSR_UPDATE_FAST_LSA_COMMANDS_HPP


