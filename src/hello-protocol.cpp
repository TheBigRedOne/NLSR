/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2026,  The University of Memphis,
 *                           Regents of the University of California
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

#include "hello-protocol.hpp"
#include "nlsr.hpp"
#include "lsdb.hpp"
#include "logger.hpp"
#include "utility/name-helper.hpp"

#include <ndn-cxx/encoding/nfd-constants.hpp>

#include <sstream>

namespace nlsr {

INIT_LOGGER(HelloProtocol);

HelloProtocol::HelloProtocol(ndn::Face& face, ndn::KeyChain& keyChain,
                             ConfParameter& confParam, RoutingTable& routingTable,
                             Lsdb& lsdb)
  : m_face(face)
  , m_scheduler(m_face.getIoContext())
  , m_keyChain(keyChain)
  , m_signingInfo(confParam.getSigningInfo())
  , m_confParam(confParam)
  , m_routingTable(routingTable)
  , m_lsdb(lsdb)
  , m_adjacencyList(m_confParam.getAdjacencyList())
{
  ndn::Name name(m_confParam.getRouterPrefix());
  name.append(NLSR_COMPONENT);
  name.append(INFO_COMPONENT);

  NLSR_LOG_DEBUG("Setting interest filter for Hello interest: " << name);

  m_face.setInterestFilter(ndn::InterestFilter(name).allowLoopback(false),
    [this] (const auto& name, const auto& interest) {
      processInterest(name, interest);
    },
    [] (const auto& name) {
      NLSR_LOG_DEBUG("Successfully registered prefix: " << name);
    },
    [] (const auto& name, const auto& resp) {
      NLSR_LOG_ERROR("Failed to register prefix " << name);
      NDN_THROW(std::runtime_error("Failed to register hello prefix: " + resp));
    },
    m_signingInfo, ndn::nfd::ROUTE_FLAG_CAPTURE);

  // Always register; handler is a no-op when event-driven verification is off.
  m_face.setInterestFilter(ndn::InterestFilter(VERIFY_NOW_PREFIX).allowLoopback(true),
    [this] (const auto&, const auto&) {
      onAttachmentChangeHint();
    },
    [] (const auto& name) {
      NLSR_LOG_DEBUG("Successfully registered prefix: " << name);
    },
    [] (const auto& name, const auto& resp) {
      NLSR_LOG_ERROR("Failed to register prefix " << name << ": " << resp);
    },
    m_signingInfo, ndn::nfd::ROUTE_FLAG_CAPTURE);
}

ndn::Name
HelloProtocol::makeHelloInterestName(const ndn::Name& neighbour) const
{
  ndn::Name interestName(neighbour);
  interestName.append(NLSR_COMPONENT);
  interestName.append(INFO_COMPONENT);
  interestName.append(ndn::tlv::GenericNameComponent, m_confParam.getRouterPrefix().wireEncode());
  return interestName;
}

ndn::Name
HelloProtocol::neighborFromHelloInterest(const ndn::Interest& interest) const
{
  return interest.getName().getPrefix(-3);
}

HelloProtocol::AdjHelloControl&
HelloProtocol::getAdjControl(const ndn::Name& neighbor)
{
  return m_adjHello[neighbor];
}

ndn::time::milliseconds
HelloProtocol::vanillaHelloLifetime() const
{
  return ndn::time::duration_cast<ndn::time::milliseconds>(
    ndn::time::seconds(m_confParam.getInterestResendTime()));
}

ndn::time::milliseconds
HelloProtocol::verifyNowLifetime() const
{
  const uint32_t timeoutMs = m_confParam.getEventDrivenVerificationTimeoutMs();
  if (timeoutMs > 0) {
    return ndn::time::milliseconds(timeoutMs);
  }
  return vanillaHelloLifetime();
}

void
HelloProtocol::expressInterest(const ndn::Name& interestName, uint32_t seconds,
                               bool isReciprocal)
{
  if (!isEventDrivenOn()) {
    expressInterestVanilla(interestName, seconds, isReciprocal);
    return;
  }

  // Owned path requires neighbour identity; Interest name is /<neighbor>/NLSR/INFO/<router>
  if (interestName.size() < 3) {
    expressInterestVanilla(interestName, seconds, isReciprocal);
    return;
  }
  ndn::Name neighbor = interestName.getPrefix(-3);
  auto& ctrl = getAdjControl(neighbor);
  expressInterestOwned(neighbor, interestName,
                       ndn::time::duration_cast<ndn::time::milliseconds>(
                         ndn::time::seconds(seconds)),
                       isReciprocal, ctrl.flowToken);
}

void
HelloProtocol::expressInterestVanilla(const ndn::Name& interestName, uint32_t seconds,
                                      bool isReciprocal)
{
  NLSR_LOG_DEBUG("Expressing Interest: " << interestName
                 << (isReciprocal ? " (reciprocal)" : ""));
  ndn::Interest interest(interestName);
  interest.setInterestLifetime(ndn::time::seconds(seconds));
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  m_face.expressInterest(interest,
    [this, isReciprocal] (const auto& interest, const auto& data) {
      onContent(interest, data, isReciprocal, 0);
    },
    [this, seconds, isReciprocal] (const auto& interest, const auto& nack) {
      NDN_LOG_TRACE("Received Nack with reason: " << nack.getReason());
      NDN_LOG_TRACE("Will treat as timeout in " << 2 * seconds << " seconds");
      m_scheduler.schedule(ndn::time::seconds(2 * seconds),
        [this, interest, isReciprocal] { processInterestTimedOut(interest, isReciprocal, 0); });
    },
    [this, isReciprocal] (const auto& interest) {
      processInterestTimedOut(interest, isReciprocal, 0);
    });

  hpIncrementSignal(Statistics::PacketType::SENT_HELLO_INTEREST);
}

void
HelloProtocol::expressInterestOwned(const ndn::Name& neighbor, const ndn::Name& interestName,
                                    ndn::time::milliseconds lifetime, bool isReciprocal,
                                    uint64_t flowToken)
{
  NLSR_LOG_DEBUG("Expressing Interest: " << interestName
                 << (isReciprocal ? " (reciprocal)" : "")
                 << " token=" << flowToken);
  ndn::Interest interest(interestName);
  interest.setInterestLifetime(lifetime);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  auto& ctrl = getAdjControl(neighbor);
  ctrl.nackDelayEvent.cancel();
  ctrl.pendingInterest = m_face.expressInterest(interest,
    [this, isReciprocal, flowToken] (const auto& interest, const auto& data) {
      onContent(interest, data, isReciprocal, flowToken);
    },
    [this, isReciprocal, flowToken, neighbor] (const auto& interest, const auto&) {
      onNackOwned(neighbor, interest, isReciprocal, flowToken);
    },
    [this, isReciprocal, flowToken] (const auto& interest) {
      processInterestTimedOut(interest, isReciprocal, flowToken);
    });

  hpIncrementSignal(Statistics::PacketType::SENT_HELLO_INTEREST);
}

void
HelloProtocol::onNackOwned(const ndn::Name& neighbor, const ndn::Interest& interest,
                           bool isReciprocal, uint64_t flowToken)
{
  auto& ctrl = getAdjControl(neighbor);
  // PendingInterestHandle::cancel is asynchronous; a superseded flow's NACK may
  // still arrive. Refuse to touch nackDelayEvent unless this token is current.
  if (flowToken != ctrl.flowToken) {
    NLSR_LOG_DEBUG("STALE HELLO CALLBACK: neighbor=" << neighbor
                   << " token=" << flowToken
                   << " current=" << ctrl.flowToken
                   << " reason=nack");
    return;
  }

  NDN_LOG_TRACE("Received Nack for " << interest.getName());
  NDN_LOG_TRACE("Will treat as timeout in " << (2 * ctrl.interestLifetime).count()
                << " milliseconds");
  ctrl.nackDelayEvent = m_scheduler.schedule(2 * ctrl.interestLifetime,
    [this, interest, isReciprocal, flowToken] {
      processInterestTimedOut(interest, isReciprocal, flowToken);
    });
}

void
HelloProtocol::sendHelloInterest(const ndn::Name& neighbor)
{
  if (!isEventDrivenOn()) {
    sendHelloInterestVanilla(neighbor);
    return;
  }
  sendHelloInterestOwned(neighbor);
}

void
HelloProtocol::sendHelloInterestVanilla(const ndn::Name& neighbor)
{
  auto adjacent = m_adjacencyList.findAdjacent(neighbor);
  if (adjacent == m_adjacencyList.end()) {
    return;
  }

  if (adjacent->getFaceId() != 0) {
    auto interestName = makeHelloInterestName(adjacent->getName());
    expressInterestVanilla(interestName, m_confParam.getInterestResendTime(), false);
    NLSR_LOG_DEBUG("Sending HELLO interest: " << interestName);
  }

  m_scheduler.schedule(ndn::time::seconds(m_confParam.getInfoInterestInterval()),
                       [this, neighbor] { sendHelloInterest(neighbor); });
}

void
HelloProtocol::sendHelloInterestOwned(const ndn::Name& neighbor)
{
  auto adjacent = m_adjacencyList.findAdjacent(neighbor);
  if (adjacent == m_adjacencyList.end()) {
    return;
  }

  auto& ctrl = getAdjControl(neighbor);
  // Periodic tick reuses the current flowToken for a new Interest only when no
  // mobility sweep owns a fresh supersede; bump token so this becomes the sole
  // authoritative flow for the adjacency.
  const uint64_t oldToken = ctrl.flowToken;
  ++ctrl.flowToken;
  ctrl.interestLifetime = vanillaHelloLifetime();
  ctrl.nackDelayEvent.cancel();
  ctrl.pendingInterest.cancel();
  NLSR_LOG_DEBUG("HELLO FLOW SUPERSEDE: neighbor=" << neighbor
                 << " oldToken=" << oldToken << " newToken=" << ctrl.flowToken
                 << " reason=periodic");

  if (adjacent->getFaceId() != 0) {
    auto interestName = makeHelloInterestName(adjacent->getName());
    expressInterestOwned(neighbor, interestName, ctrl.interestLifetime,
                         false, ctrl.flowToken);
    NLSR_LOG_DEBUG("Sending HELLO interest: " << interestName);
  }

  ctrl.periodicEvent = m_scheduler.schedule(
    ndn::time::seconds(m_confParam.getInfoInterestInterval()),
    [this, neighbor] { sendHelloInterest(neighbor); });
}

void
HelloProtocol::requestVerificationNow(const ndn::Name& neighbor)
{
  auto adjacent = m_adjacencyList.findAdjacent(neighbor);
  if (adjacent == m_adjacencyList.end()) {
    noteSweepResult(neighbor, VerifyResult::INDETERMINATE);
    return;
  }

  auto& ctrl = getAdjControl(neighbor);
  const uint64_t oldToken = ctrl.flowToken;
  ++ctrl.flowToken;
  ctrl.interestLifetime = verifyNowLifetime();
  ctrl.nackDelayEvent.cancel();
  ctrl.pendingInterest.cancel();
  ctrl.periodicEvent.cancel();
  m_adjacencyList.setTimedOutInterestCount(neighbor, 0);

  NLSR_LOG_INFO("HELLO FLOW SUPERSEDE: neighbor=" << neighbor
                << " oldToken=" << oldToken << " newToken=" << ctrl.flowToken
                << " reason=verify-now");

  if (adjacent->getFaceId() == 0) {
    // No Face to probe. Face-destroy path should already have marked INACTIVE;
    // treat as decisive UNREACHABLE for the sweep when status is not ACTIVE.
    if (adjacent->getStatus() != Adjacent::STATUS_ACTIVE) {
      noteSweepResult(neighbor, VerifyResult::UNREACHABLE);
    }
    else {
      noteSweepResult(neighbor, VerifyResult::INDETERMINATE);
    }
    ctrl.periodicEvent = m_scheduler.schedule(
      ndn::time::seconds(m_confParam.getInfoInterestInterval()),
      [this, neighbor] { sendHelloInterest(neighbor); });
    return;
  }

  auto interestName = makeHelloInterestName(adjacent->getName());
  expressInterestOwned(neighbor, interestName, ctrl.interestLifetime,
                       false, ctrl.flowToken);
  ctrl.periodicEvent = m_scheduler.schedule(
    ndn::time::seconds(m_confParam.getInfoInterestInterval()),
    [this, neighbor] { sendHelloInterest(neighbor); });
}

void
HelloProtocol::processInterest(const ndn::Name& name,
                               const ndn::Interest& interest)
{
  const ndn::Name interestName = interest.getName();

  hpIncrementSignal(Statistics::PacketType::RCV_HELLO_INTEREST);

  NLSR_LOG_DEBUG("Interest received for Name: " << interestName);
  if (interestName.get(-2).toUri() != INFO_COMPONENT) {
    NLSR_LOG_DEBUG("INFO_COMPONENT not found or Interest Name " << interestName
                   << " does not match expression");
    return;
  }

  ndn::Name neighbor(interestName.get(-1).blockFromValue());
  NLSR_LOG_DEBUG("Neighbor: " << neighbor);
  if (m_adjacencyList.isNeighbor(neighbor)) {
    auto data = std::make_shared<ndn::Data>();
    data->setName(ndn::Name(interest.getName()).appendVersion());
    data->setFreshnessPeriod(0_ms);
    data->setContent(ndn::make_span(reinterpret_cast<const uint8_t*>(INFO_COMPONENT.data()),
                                    INFO_COMPONENT.size()));

    m_keyChain.sign(*data, m_signingInfo);

    NLSR_LOG_DEBUG("Sending out data for name: " << interest.getName());
    m_face.put(*data);
    hpIncrementSignal(Statistics::PacketType::SENT_HELLO_DATA);

    auto adjacent = m_adjacencyList.findAdjacent(neighbor);
    if (adjacent->getStatus() == Adjacent::STATUS_INACTIVE) {
      if (adjacent->getFaceId() != 0) {
        if (!isEventDrivenOn()) {
          expressInterestVanilla(makeHelloInterestName(neighbor),
                                 m_confParam.getInterestResendTime(), true);
        }
        else {
          auto& ctrl = getAdjControl(neighbor);
          const uint64_t oldToken = ctrl.flowToken;
          ++ctrl.flowToken;
          ctrl.interestLifetime = vanillaHelloLifetime();
          ctrl.nackDelayEvent.cancel();
          ctrl.pendingInterest.cancel();
          NLSR_LOG_DEBUG("HELLO FLOW SUPERSEDE: neighbor=" << neighbor
                         << " oldToken=" << oldToken << " newToken=" << ctrl.flowToken
                         << " reason=reciprocal");
          expressInterestOwned(neighbor, makeHelloInterestName(neighbor),
                               ctrl.interestLifetime, true, ctrl.flowToken);
        }
      }
    }
  }
}

void
HelloProtocol::processInterestTimedOut(const ndn::Interest& interest, bool isReciprocal,
                                       uint64_t flowToken)
{
  const ndn::Name interestName(interest.getName());
  NLSR_LOG_DEBUG("Interest timed out for Name: " << interestName);
  if (interestName.get(-2).toUri() != INFO_COMPONENT) {
    return;
  }
  ndn::Name neighbor = interestName.getPrefix(-3);

  if (isEventDrivenOn()) {
    auto& ctrl = getAdjControl(neighbor);
    if (flowToken != ctrl.flowToken) {
      NLSR_LOG_DEBUG("STALE HELLO CALLBACK: neighbor=" << neighbor
                     << " token=" << flowToken
                     << " current=" << ctrl.flowToken
                     << " reason=timeout");
      return;
    }
  }

  NLSR_LOG_DEBUG("Neighbor: " << neighbor);
  m_adjacencyList.incrementTimedOutInterestCount(neighbor);

  Adjacent::Status status = m_adjacencyList.getStatusOfNeighbor(neighbor);

  uint32_t infoIntTimedOutCount = m_adjacencyList.getTimedOutInterestCount(neighbor);
  NLSR_LOG_DEBUG("Status: " << status);
  NLSR_LOG_DEBUG("Info Interest Timed out: " << infoIntTimedOutCount);
  if (infoIntTimedOutCount < m_confParam.getInterestRetryNumber()) {
    auto retryName = makeHelloInterestName(neighbor);
    NLSR_LOG_DEBUG("Resending interest: " << retryName);
    if (!isEventDrivenOn()) {
      expressInterestVanilla(retryName, m_confParam.getInterestResendTime(), isReciprocal);
    }
    else {
      auto& ctrl = getAdjControl(neighbor);
      expressInterestOwned(neighbor, retryName, ctrl.interestLifetime,
                           isReciprocal, flowToken);
    }
  }
  else {
    if (status == Adjacent::STATUS_ACTIVE) {
      m_adjacencyList.setStatusOfNeighbor(neighbor, Adjacent::STATUS_INACTIVE);

      NLSR_LOG_DEBUG("Neighbor: " << neighbor << " status changed to INACTIVE");

      if (m_confParam.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
        m_routingTable.scheduleRoutingTableCalculation();
      }
      else {
        m_lsdb.scheduleAdjLsaBuild();
      }
    }

    if (isEventDrivenOn()) {
      noteSweepResult(neighbor, VerifyResult::UNREACHABLE);
    }
  }
}

void
HelloProtocol::onContent(const ndn::Interest& interest, const ndn::Data& data,
                         bool isReciprocal, uint64_t flowToken)
{
  NLSR_LOG_DEBUG("Received data for INFO(name): " << data.getName());
  auto kl = data.getKeyLocator();
  if (kl && kl->getType() == ndn::tlv::Name) {
    NLSR_LOG_DEBUG("Data signed with: " << kl->getName());
  }
  m_confParam.getValidator().validate(data,
                                      [this, isReciprocal, flowToken] (const auto& validatedData) {
                                        onContentValidated(validatedData, isReciprocal, flowToken);
                                      },
                                      [this, flowToken] (const auto& rejectedData, const auto& ve) {
                                        onContentValidationFailed(rejectedData, ve, flowToken);
                                      });
}

void
HelloProtocol::onContentValidated(const ndn::Data& data, bool isReciprocal, uint64_t flowToken)
{
  ndn::Name dataName = data.getName();
  NLSR_LOG_DEBUG("Data validation successful for INFO(name): " << dataName);

  if (dataName.get(-3).toUri() != INFO_COMPONENT) {
    return;
  }

  ndn::Name neighbor = dataName.getPrefix(-4);

  if (isEventDrivenOn()) {
    auto& ctrl = getAdjControl(neighbor);
    if (flowToken != ctrl.flowToken) {
      NLSR_LOG_DEBUG("STALE HELLO CALLBACK: neighbor=" << neighbor
                     << " token=" << flowToken
                     << " current=" << ctrl.flowToken
                     << " reason=data");
      return;
    }
  }

  Adjacent::Status oldStatus = m_adjacencyList.getStatusOfNeighbor(neighbor);
  m_adjacencyList.setStatusOfNeighbor(neighbor, Adjacent::STATUS_ACTIVE);
  m_adjacencyList.setTimedOutInterestCount(neighbor, 0);
  Adjacent::Status newStatus = m_adjacencyList.getStatusOfNeighbor(neighbor);

  NLSR_LOG_DEBUG("Neighbor: " << neighbor);
  NLSR_LOG_DEBUG("Old Status: " << oldStatus << ", New Status: " << newStatus);
  if ((oldStatus - newStatus) != 0) {
    if (m_confParam.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
      m_routingTable.scheduleRoutingTableCalculation();
    }
    else {
      m_lsdb.scheduleAdjLsaBuild();
    }
    onInitialHelloDataValidated(neighbor);
  }

  if (isReciprocal &&
      m_confParam.getResultDrivenAdjLsaBuild() &&
      m_confParam.getHyperbolicState() != HYPERBOLIC_STATE_ON) {
    if (isEventDrivenOn() && m_sweep.has_value()) {
      NLSR_LOG_DEBUG("Reciprocal Hello validated for " << neighbor
                     << "; immediate Adj-LSA deferred while mobility sweep is active");
    }
    else {
      NLSR_LOG_DEBUG("Reciprocal Hello validated for " << neighbor
                     << "; requesting immediate Adjacency LSA build if dirty");
      m_lsdb.requestImmediateAdjLsaBuild();
    }
  }

  if (isEventDrivenOn()) {
    noteSweepResult(neighbor, VerifyResult::REACHABLE);
  }
  // increment RCV_HELLO_DATA
  hpIncrementSignal(Statistics::PacketType::RCV_HELLO_DATA);
}

void
HelloProtocol::onContentValidationFailed(const ndn::Data& data,
                                         const ndn::security::ValidationError& ve,
                                         uint64_t flowToken)
{
  NLSR_LOG_DEBUG("Validation error: " << ve);
  if (!isEventDrivenOn() || data.getName().size() < 4) {
    return;
  }
  if (data.getName().get(-3).toUri() != INFO_COMPONENT) {
    return;
  }
  ndn::Name neighbor = data.getName().getPrefix(-4);
  auto& ctrl = getAdjControl(neighbor);
  if (flowToken != ctrl.flowToken) {
    NLSR_LOG_DEBUG("STALE HELLO CALLBACK: neighbor=" << neighbor
                   << " token=" << flowToken
                   << " current=" << ctrl.flowToken
                   << " reason=validation-failure");
    return;
  }
  noteSweepResult(neighbor, VerifyResult::INDETERMINATE);
}

void
HelloProtocol::onAttachmentChangeHint()
{
  if (!isEventDrivenOn()) {
    return;
  }
  beginMobilitySweep();
}

void
HelloProtocol::onAdjacentFaceDestroyed(const ndn::Name& neighbor)
{
  if (!isEventDrivenOn() || !m_sweep.has_value()) {
    return;
  }
  if (m_sweep->targets.count(neighbor) == 0) {
    return;
  }

  // End the authoritative Hello flow before recording UNREACHABLE so a late
  // Data/timeout for the destroyed face cannot revive ACTIVE or overwrite the
  // sweep result (approved face-destroy + current-token invariants).
  auto& ctrl = getAdjControl(neighbor);
  const uint64_t oldToken = ctrl.flowToken;
  ++ctrl.flowToken;
  ctrl.nackDelayEvent.cancel();
  ctrl.pendingInterest.cancel();
  NLSR_LOG_INFO("HELLO FLOW SUPERSEDE: neighbor=" << neighbor
                << " oldToken=" << oldToken << " newToken=" << ctrl.flowToken
                << " reason=face-destroy");

  noteSweepResult(neighbor, VerifyResult::UNREACHABLE);
}

std::set<ndn::Name>
HelloProtocol::buildSweepTargets() const
{
  std::set<ndn::Name> targets;
  for (const auto& adj : m_adjacencyList.getAdjList()) {
    if (adj.getStatus() == Adjacent::STATUS_ACTIVE || adj.getFaceId() != 0) {
      targets.insert(adj.getName());
    }
  }
  return targets;
}

void
HelloProtocol::beginMobilitySweep()
{
  if (m_sweep.has_value()) {
    NLSR_LOG_INFO("MOBILITY VERIFICATION: replacing serial=" << m_sweep->serial);
    // Publication hold stays active across serial replacement; only release on
    // settle/abort of the newest sweep.
  }
  else {
    m_lsdb.holdAdjLsaBuild();
  }

  MobilitySweep sweep;
  sweep.serial = m_nextSweepSerial++;
  sweep.targets = buildSweepTargets();
  m_sweep = std::move(sweep);

  std::ostringstream oss;
  for (const auto& t : m_sweep->targets) {
    oss << t << " ";
  }
  NLSR_LOG_INFO("MOBILITY VERIFICATION START: serial=" << m_sweep->serial
                << " targets=[" << oss.str() << "]");

  if (m_sweep->targets.empty()) {
    abortMobilitySweep("empty-target-set");
    return;
  }

  const auto targets = m_sweep->targets;
  for (const auto& neighbor : targets) {
    // requestVerificationNow may abort the sweep (INDETERMINATE). Do not continue
    // issuing verify-now probes after publication authority has returned to ordinary.
    if (!m_sweep.has_value()) {
      return;
    }
    requestVerificationNow(neighbor);
  }
}

void
HelloProtocol::abortMobilitySweep(const std::string& reason)
{
  if (!m_sweep.has_value()) {
    return;
  }
  NLSR_LOG_INFO("MOBILITY VERIFICATION ABORT: serial=" << m_sweep->serial
                << " reason=" << reason);
  m_sweep.reset();
  m_lsdb.releaseAdjLsaBuildHold(false);
}

void
HelloProtocol::noteSweepResult(const ndn::Name& neighbor, VerifyResult result)
{
  if (!m_sweep.has_value()) {
    return;
  }
  if (m_sweep->targets.count(neighbor) == 0) {
    return;
  }

  const char* label = "INDETERMINATE";
  if (result == VerifyResult::REACHABLE) {
    label = "REACHABLE";
  }
  else if (result == VerifyResult::UNREACHABLE) {
    label = "UNREACHABLE";
  }

  auto& ctrl = getAdjControl(neighbor);
  NLSR_LOG_INFO("HELLO VERIFY RESULT: serial=" << m_sweep->serial
                << " neighbor=" << neighbor
                << " token=" << ctrl.flowToken
                << " result=" << label);

  if (result == VerifyResult::INDETERMINATE) {
    abortMobilitySweep("indeterminate-result");
    return;
  }

  m_sweep->results[neighbor] = result;
  checkSweepCompletion();
}

void
HelloProtocol::checkSweepCompletion()
{
  if (!m_sweep.has_value()) {
    return;
  }

  for (const auto& target : m_sweep->targets) {
    if (m_sweep->results.find(target) == m_sweep->results.end()) {
      return;
    }
  }

  NLSR_LOG_INFO("MOBILITY VERIFICATION COMPLETE: serial=" << m_sweep->serial);
  m_sweep.reset();
  m_lsdb.releaseAdjLsaBuildHold(true);
}

} // namespace nlsr
