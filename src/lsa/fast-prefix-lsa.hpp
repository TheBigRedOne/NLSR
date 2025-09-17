/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef NLSR_LSA_FAST_PREFIX_LSA_HPP
#define NLSR_LSA_FAST_PREFIX_LSA_HPP

#include "lsa.hpp"
#include "name-prefix-list.hpp"
#include "../tlv-nlsr.hpp"

namespace nlsr {

class FastPrefixLsa : public Lsa
{
public:
  FastPrefixLsa() = default;

  FastPrefixLsa(const ndn::Name& originRouter, uint64_t seqNo,
                const ndn::time::system_clock::time_point& timepoint,
                const std::vector<ndn::Name>& prefixes,
                const std::optional<ndn::Name>& neighborRouterName,
                const std::optional<uint32_t>& newFaceSeq);

  explicit
  FastPrefixLsa(const ndn::Block& wire);

  Lsa::Type
  getType() const override
  {
    return type();
  }

  static constexpr Lsa::Type
  type()
  {
    return Lsa::Type::FAST_PREFIX;
  }

  const std::vector<ndn::Name>&
  getPrefixes() const { return m_prefixes; }

  const std::optional<ndn::Name>&
  getNeighborRouterName() const { return m_neighborRouterName; }

  const std::optional<uint32_t>&
  getNewFaceSeq() const { return m_newFaceSeq; }

  template<ndn::encoding::Tag TAG>
  size_t
  wireEncode(ndn::EncodingImpl<TAG>& encoder) const;

  const ndn::Block&
  wireEncode() const override;

  void
  wireDecode(const ndn::Block& wire);

  std::tuple<bool, std::list<ndn::Name>, std::list<ndn::Name>>
  update(const std::shared_ptr<Lsa>& lsa) override;

private:
  void
  print(std::ostream& os) const override;

private:
  std::vector<ndn::Name> m_prefixes;
  std::optional<ndn::Name> m_neighborRouterName;
  std::optional<uint32_t> m_newFaceSeq;
};

NDN_CXX_DECLARE_WIRE_ENCODE_INSTANTIATIONS(FastPrefixLsa);

} // namespace nlsr

#endif // NLSR_LSA_FAST_PREFIX_LSA_HPP
