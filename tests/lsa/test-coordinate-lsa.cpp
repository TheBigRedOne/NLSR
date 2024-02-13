/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2024,  The University of Memphis,
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

#include "lsa/coordinate-lsa.hpp"

#include "tests/boost-test.hpp"

namespace nlsr::tests {

/*
static void
printBytes(ndn::span<const uint8_t> buf)
{
  std::string hex = ndn::toHex(buf);

  for (size_t i = 0; i < hex.size(); i++) {
    if (i > 0 && i % 30 == 0)
      std::cout << "\n  ";

    std::cout << "0x" << hex[i];
    std::cout << hex[++i];

    if ((i + 1) != hex.size())
      std::cout << ", ";
  }
  std::cout << "\n" << "};" << std::endl;
}

printBytes(block);
*/

BOOST_AUTO_TEST_SUITE(TestCoordinateLsa)

const uint8_t COORDINATE_LSA1[] = {
  0x85, 0x43, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
  0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
  0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x04, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x88, 0x08, 0x40, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
  0x08, 0x40, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t COORDINATE_LSA_DIFF_ANGLE[] = {
  0x85, 0x39, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
  0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
  0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x04, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x88, 0x08, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t COORDINATE_LSA_DIFF_RADIUS[] = {
  0x85, 0x39, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
  0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
  0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x02, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x88, 0x08, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t COORDINATE_LSA_DIFF_SEQ[] = {
  0x85, 0x39, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
  0x82, 0x01, 0x0E, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
  0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x02, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x88, 0x08, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t COORDINATE_LSA_DIFF_TS[] = {
  0x85, 0x39, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
  0x82, 0x01, 0x0E, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
  0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x34, 0x34, 0x87, 0x08, 0x40, 0x02, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x88, 0x08, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

BOOST_AUTO_TEST_CASE(Basic)
{
  auto testTimePoint = ndn::time::fromUnixTimestamp(ndn::time::milliseconds(1585196014943));
  std::vector<double> angles1{30.0}, angles2{30.0};
  angles1.push_back(30.0);
  angles2.push_back(30.0);
  CoordinateLsa clsa1("router1", 12, testTimePoint, 2.5, angles1);
  CoordinateLsa clsa2("router1", 12, testTimePoint, 2.5, angles2);

  BOOST_CHECK_CLOSE(clsa1.getRadius(), 2.5, 0.0001);
  BOOST_TEST(clsa1.getTheta() == angles1, boost::test_tools::per_element());

  BOOST_CHECK_EQUAL(clsa1, clsa2);

  BOOST_CHECK_EQUAL(clsa1.wireEncode(), clsa2.wireEncode());

  auto wire = clsa1.wireEncode();
  BOOST_TEST(wire == COORDINATE_LSA1, boost::test_tools::per_element());

  std::vector<double> angles3{40.0};
  clsa1.setTheta(angles3);
  wire = clsa1.wireEncode();
  BOOST_TEST(wire == COORDINATE_LSA_DIFF_ANGLE, boost::test_tools::per_element());

  clsa1.setRadius(2.3);
  wire = clsa1.wireEncode();
  BOOST_TEST(wire == COORDINATE_LSA_DIFF_RADIUS, boost::test_tools::per_element());

  clsa1.setSeqNo(14);
  wire = clsa1.wireEncode();
  BOOST_TEST(wire == COORDINATE_LSA_DIFF_SEQ, boost::test_tools::per_element());

  testTimePoint = ndn::time::fromUnixTimestamp(ndn::time::milliseconds(1585196024993));
  clsa1.setExpirationTimePoint(testTimePoint);
  wire = clsa1.wireEncode();
  BOOST_TEST(wire == COORDINATE_LSA_DIFF_TS, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(InitializeFromContent)
{
  auto testTimePoint = ndn::time::system_clock::now();
  std::vector<double> angles = {30, 40.0};
  CoordinateLsa clsa1("router1", 12, testTimePoint, 2.5, angles);
  CoordinateLsa clsa2(clsa1.wireEncode());
  BOOST_CHECK_EQUAL(clsa1.wireEncode(), clsa2.wireEncode());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace nlsr::tests
