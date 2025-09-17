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

#ifndef NLSR_LSA_FAST_LSA_HPP
#define NLSR_LSA_FAST_LSA_HPP

#include "lsa.hpp"

namespace nlsr {
namespace lsa {

/**
 * @brief A class for FastLSA
 *
 * FastLSA is used for rapid propagation of temporary routes from OptoFlood.
 */
class FastLsa : public Lsa
{
public:
  /**
   * @brief Construct a FastLsa with default values.
   */
  FastLsa();

  /**
   * @brief Get the name prefix advertised by the LSA.
   * @returns The name prefix.
   */
  const ndn::Name&
  getName() const;

  /**
   * @brief Set the name prefix to be advertised by the LSA.
   * @param name The name prefix.
   */
  void
  setName(const ndn::Name& name);

  /**
   * @brief Get the face ID for the route.
   * @returns The face ID.
   */
  uint64_t
  getFaceId() const;

  /**
   * @brief Set the face ID for the route.
   * @param faceId The face ID.
   */
  void
  setFaceId(uint64_t faceId);

  /**
   * @brief Get the expiration period of the LSA.
   * @returns The expiration period.
   */
  ndn::time::milliseconds
  getExpirationPeriod() const;

  /**
   * @brief Set the expiration period of the LSA.
   * @param expirationPeriod The expiration period.
   */
  void
  setExpirationPeriod(ndn::time::milliseconds expirationPeriod);

  // 覆盖基类编码接口
  const ndn::Block&
  wireEncode() const override;

  void
  wireDecode(const ndn::Block& block);

  ndn::Name
  getFullName() const;

private:
  ndn::Name m_name;
  uint64_t m_faceId;
  ndn::time::milliseconds m_expirationPeriod;
};

} // namespace lsa
} // namespace nlsr

#endif // NLSR_LSA_FAST_LSA_HPP
