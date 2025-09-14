/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2021,  The University of Memphis,
 *                           Regents of the University of California,
 *                           Arizona Board of Regents.
 *
 * This file is part of NLSR (Named-data Link State Routing).
 * See AUTHORS.md for complete list of NLSR authors and contributors.
 *
 * NLSR is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NLSR is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NLSR, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nfd-rib-command-processor.hpp"

#include "lsa/name-lsa.hpp"
#include "lsa/fast-lsa.hpp"
#include <ndn-cxx/util/logging.hpp>

NDN_LOG_INIT(nlsr.NfdRibCommandProcessor);

namespace nlsr {
namespace update {

NfdRibCommandProcessor::NfdRibCommandProcessor(ndn::mgmt::Dispatcher& dispatcher,
                                               NamePrefixList& namePrefixList,
                                               Lsdb& lsdb)
  : CommandManagerBase(dispatcher, namePrefixList, lsdb, "rib")
{
  m_dispatcher.addControlCommand<ndn::nfd::ControlParameters>(makeRelPrefix("register"),
    ndn::mgmt::makeAcceptAllAuthorization(),
    std::bind(&NfdRibCommandProcessor::validateParameters<NfdRibRegisterCommand>, this, _1),
    std::bind(&NfdRibCommandProcessor::processRibRegister, this, _1, _2, _3, _4));

  m_dispatcher.addControlCommand<ndn::nfd::ControlParameters>(makeRelPrefix("unregister"),
    ndn::mgmt::makeAcceptAllAuthorization(),
    std::bind(&NfdRibCommandProcessor::validateParameters<NfdRibUnregisterCommand>, this, _1),
    std::bind(&NfdRibCommandProcessor::withdrawAndRemovePrefix, this, _1, _2, _3, _4));
}

void
NfdRibCommandProcessor::processRibRegister(const ndn::nfd::ControlParameters& params,
                                           const ndn::nfd::ControlResponse& response,
                                           ndn::mgmt::Dispatcher::Session& session,
                                           ndn::mgmt::Dispatcher::Completion completion)
{
  if (params.getOrigin() == ndn::nfd::ROUTE_ORIGIN_OPTOFLOOD) {
    NDN_LOG_DEBUG("Received OptoFlood RIB registration for " << params.getName());
    this->generateFastLsa(params, response, session, completion);
  }
  else {
    NDN_LOG_DEBUG("Received normal RIB registration for " << params.getName());
    this->advertiseAndInsertPrefix(params, response, session, completion);
  }
}

void
NfdRibCommandProcessor::generateFastLsa(const ndn::nfd::ControlParameters& params,
                                        const ndn::nfd::ControlResponse& response,
                                        ndn::mgmt::Dispatcher::Session& session,
                                        ndn::mgmt::Dispatcher::Completion completion)
{
  // 1. Create FastLsa
  auto lsa = make_shared<lsa::FastLsa>();
  lsa->setName(params.getName());
  lsa->setOriginRouter(m_lsdb.getOriginRouter());
  lsa->setFaceId(params.getFaceId());
  lsa->setSequence(m_lsdb.getLsaSeq(lsa::Lsa::LsaType::FAST));
  lsa->setExpirationPeriod(params.getExpirationPeriod());

  // 2. Add to LSDB and flood
  if (m_lsdb.addLsa(lsa)) {
    NDN_LOG_INFO("Generated and flooding FastLSA for " << lsa->getName());
  }
  else {
    NDN_LOG_DEBUG("Duplicate FastLSA for " << lsa->getName() << ", not flooding");
  }

  // 3. Send back response
  session.send(response, completion);
}

} // namespace update
} // namespace nlsr
