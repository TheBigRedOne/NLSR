/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2024, The University of Glasgow
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
 **/

#include "fast-lsa.hpp"
#include "tlv-nlsr.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace nlsr {
namespace lsa {

using ndn::encoding::appendNonNegativeInteger;
using ndn::encoding::readNonNegativeInteger;

FastLsa::FastLsa()
  : Lsa(Lsa::LsaType::FAST)
  , m_faceId(0)
  , m_expirationPeriod(1000) // Default to 1000ms
{
}

const ndn::Name&
FastLsa::getName() const
{
  return m_name;
}

void
FastLsa::setName(const ndn::Name& name)
{
  m_name = name;
}

uint64_t
FastLsa::getFaceId() const
{
  return m_faceId;
}

void
FastLsa::setFaceId(uint64_t faceId)
{
  m_faceId = faceId;
}

ndn::time::milliseconds
FastLsa::getExpirationPeriod() const
{
  return m_expirationPeriod;
}

void
FastLsa::setExpirationPeriod(ndn::time::milliseconds expirationPeriod)
{
  m_expirationPeriod = expirationPeriod;
}

void
FastLsa::wireEncode(ndn::Block& block) const
{
  ndn::encoding::Encoder encoder(block);

  encoder.prependVarNumber(getSequence());
  encoder.prependBlock(tlv::SequenceNumber);

  encoder.prependVarNumber(m_expirationPeriod.count());
  encoder.prependBlock(tlv::ExpirationPeriod);

  encoder.prependVarNumber(m_faceId);
  encoder.prependBlock(tlv::FaceId);

  m_name.wireEncode(encoder);

  encoder.prependBlock(tlv::FastLsa);
}

void
FastLsa::wireDecode(const ndn::Block& block)
{
  block.parse();

  for (const auto& el : block.elements()) {
    switch (el.type()) {
      case tlv::FastLsa:
        wireDecode(el);
        break;
      case ndn::tlv::Name:
        m_name.wireDecode(el);
        break;
      case tlv::FaceId:
        m_faceId = readNonNegativeInteger(el);
        break;
      case tlv::ExpirationPeriod:
        m_expirationPeriod = ndn::time::milliseconds(readNonNegativeInteger(el));
        break;
      case tlv::SequenceNumber:
        setSequence(readNonNegativeInteger(el));
        break;
      default:
        // Ignore unknown TLV
        break;
    }
  }
}

ndn::Name
FastLsa::getFullName() const
{
  return getOriginRouter().getPrefix(getOriginRouter().size() - 2)
    .append("LSA")
    .append(ndn::to_string(static_cast<uint64_t>(getType())))
    .append(getOriginRouter().get(-1))
    .append(ndn::to_string(getSequence()));
}

} // namespace lsa
} // namespace nlsr
