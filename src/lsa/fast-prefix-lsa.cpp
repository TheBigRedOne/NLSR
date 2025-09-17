/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "fast-prefix-lsa.hpp"

#include "../tlv-nlsr.hpp"

namespace nlsr {

template<ndn::encoding::Tag TAG>
size_t
FastPrefixLsa::wireEncode(ndn::EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  // Encode FastPrefix entries
  for (auto it = m_prefixes.rbegin(); it != m_prefixes.rend(); ++it) {
    ndn::EncodingEstimator estimator;
    size_t innerLen = 0;

    // Prefix (Name)
    innerLen += it->wireEncode(encoder);

    // NeighborRouterName (optional)
    if (m_neighborRouterName) {
      innerLen += m_neighborRouterName->wireEncode(encoder);
    }

    // NewFaceSeq (optional)
    if (m_newFaceSeq) {
      innerLen += prependNonNegativeIntegerBlock(encoder, nlsr::tlv::SequenceNumber, *m_newFaceSeq);
    }

    innerLen += encoder.prependVarNumber(innerLen);
    innerLen += encoder.prependVarNumber(nlsr::tlv::FastPrefixEntry);

    totalLength += innerLen;
  }

  // Base LSA
  totalLength += Lsa::wireEncode(encoder);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(nlsr::tlv::FastPrefixLsa);

  return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(FastPrefixLsa);

const ndn::Block&
FastPrefixLsa::wireEncode() const
{
  if (m_wire.hasWire()) {
    return m_wire;
  }

  ndn::EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  ndn::EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
FastPrefixLsa::wireDecode(const ndn::Block& wire)
{
  m_prefixes.clear();
  m_neighborRouterName.reset();
  m_newFaceSeq.reset();

  ndn::Block outer = wire;
  outer.parse();

  if (outer.type() != nlsr::tlv::FastPrefixLsa) {
    NDN_THROW(Error("FastPrefixLsa wrong TLV"));
  }

  auto it = outer.elements_begin();
  if (it == outer.elements_end() || it->type() != nlsr::tlv::Lsa) {
    NDN_THROW(Error("Missing Lsa base block"));
  }
  Lsa::wireDecode(*it);
  ++it;

  // Entries
  for (; it != outer.elements_end() && it->type() == nlsr::tlv::FastPrefixEntry; ++it) {
    it->parse();
    auto jt = it->elements_begin();

    // NeighborRouterName (optional, Name)
    if (jt != it->elements_end() && jt->type() == ndn::tlv::Name) {
      ndn::Name maybeName;
      maybeName.wireDecode(*jt);
      // Heuristic: the first Name is considered Prefix, the second optional one neighbor
      // We decode two Names if present
      m_prefixes.emplace_back(maybeName);
      ++jt;
      if (jt != it->elements_end() && jt->type() == ndn::tlv::Name) {
        ndn::Name nbr;
        nbr.wireDecode(*jt);
        m_neighborRouterName = nbr;
        ++jt;
      }
    }

    // NewFaceSeq (optional)
    for (; jt != it->elements_end(); ++jt) {
      if (jt->type() == nlsr::tlv::SequenceNumber) {
        m_newFaceSeq = ndn::readNonNegativeIntegerAs<uint32_t>(*jt);
      }
    }
  }
}

std::tuple<bool, std::list<ndn::Name>, std::list<ndn::Name>>
FastPrefixLsa::update(const std::shared_ptr<Lsa>& lsa)
{
  auto other = std::static_pointer_cast<FastPrefixLsa>(lsa);
  bool changed = false;
  std::list<ndn::Name> addList;
  std::list<ndn::Name> remList;

  // Simple replace: compute diff by set
  std::set<ndn::Name> a(m_prefixes.begin(), m_prefixes.end());
  std::set<ndn::Name> b(other->m_prefixes.begin(), other->m_prefixes.end());

  for (const auto& p : b) {
    if (!a.count(p)) { addList.push_back(p); changed = true; }
  }
  for (const auto& p : a) {
    if (!b.count(p)) { remList.push_back(p); changed = true; }
  }

  m_prefixes = other->m_prefixes;
  m_neighborRouterName = other->m_neighborRouterName;
  m_newFaceSeq = other->m_newFaceSeq;
  m_wire.reset();

  return {changed, addList, remList};
}

FastPrefixLsa::FastPrefixLsa(const ndn::Name& originRouter, uint64_t seqNo,
                             const ndn::time::system_clock::time_point& timepoint,
                             const std::vector<ndn::Name>& prefixes,
                             const std::optional<ndn::Name>& neighborRouterName,
                             const std::optional<uint32_t>& newFaceSeq)
  : Lsa(originRouter, seqNo, timepoint)
  , m_prefixes(prefixes)
  , m_neighborRouterName(neighborRouterName)
  , m_newFaceSeq(newFaceSeq)
{
}

FastPrefixLsa::FastPrefixLsa(const ndn::Block& wire)
{
  wireDecode(wire);
}

void
FastPrefixLsa::print(std::ostream& os) const
{
  os << "      Prefixes            : ";
  for (const auto& p : m_prefixes) {
    os << p << " ";
  }
  os << "\n";
  if (m_neighborRouterName) {
    os << "      NeighborRouterName  : " << *m_neighborRouterName << "\n";
  }
  if (m_newFaceSeq) {
    os << "      NewFaceSeq          : " << *m_newFaceSeq << "\n";
  }
}

} // namespace nlsr
