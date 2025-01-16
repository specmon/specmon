// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package rule_test

import (
	"testing"

	"github.com/specmon/specmon/rule"
)

/*
	func TestTranslation(t *testing.T) {
		type translationTest struct {
			src         rule.Rule
			dst         []*rule.Rule
			expectError bool
		}

		translationTests := []translationTest{
			{
				// [ State0(m), Fr(k) ] --> [ Out(c, len(hmac(k, payload(m)))), State1(k, m) ]
				rule.Rule{
					Name: "R",
					LHS:  []*term.Function{term.NewFunction("Fr", []term.Term{term.NewVariable("k")}), term.NewFunction("State0", []term.Term{term.NewVariable("m")})},
					Act:  nil,
					RHS:  []*term.Function{term.NewFunction("Out", []term.Term{term.NewVariable("c"), term.NewFunction("len", []term.Term{term.NewFunction("hmac", []term.Term{term.NewVariable("k"), term.NewFunction("payload", []term.Term{term.NewVariable("m")})})})}), term.NewFunction("State1", []term.Term{term.NewVariable("k"), term.NewVariable("m")})},
				},
				[]*rule.Rule{
					{
						Name: "R_prologue",
						LHS:  []*term.Function{term.NewFunction("State0", []term.Term{term.NewVariable("m")})},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("Fr"), term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
							term.NewFunction("Fn", []term.Term{term.NewConstant("payload"), term.NewFunction("", []term.Term{term.NewVariable("m")}), term.NewFunction("", []term.Term{term.NewVariable("payloadm")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("Fr_Pre", []term.Term{}),
							term.NewFunction("State0_0", []term.Term{term.NewVariable("m")}),
							term.NewFunction("State0_1", []term.Term{term.NewVariable("m")}),
						},
					},
					{
						Name: "R_epilogue",
						LHS: []*term.Function{
							term.NewFunction("Fr_0", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
							term.NewFunction("State0_0", []term.Term{term.NewVariable("m")}),
							term.NewFunction("len", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")}), term.NewFunction("", []term.Term{term.NewVariable("lenhmacpayloadm")})}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("Out"), term.NewFunction("", []term.Term{term.NewVariable("c"), term.NewVariable("lenhmacpayloadm")}), term.NewFunction("", []term.Term{})}),
						},
						RHS: []*term.Function{
							term.NewFunction("Out", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("c"), term.NewVariable("lenhmacpayloadm")}), term.NewFunction("", []term.Term{})}),
							term.NewFunction("State1", []term.Term{term.NewVariable("k"), term.NewVariable("m")}),
						},
					},
					{
						Name: "R_0",
						LHS: []*term.Function{
							term.NewFunction("Fr_Pre", []term.Term{}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("Fr"), term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
						},
						RHS: []*term.Function{
							term.NewFunction("Fr_0", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
							term.NewFunction("Fr_1", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
						},
					},
					{
						Name: "R_1",
						LHS: []*term.Function{
							term.NewFunction("hmac", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k"), term.NewVariable("payloadm")}), term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")})}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("len"), term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")}), term.NewFunction("", []term.Term{term.NewVariable("lenhmacpayloadm")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("len", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")}), term.NewFunction("", []term.Term{term.NewVariable("lenhmacpayloadm")})}),
						},
					},
					{
						Name: "R_2",
						LHS: []*term.Function{
							term.NewFunction("Fr_1", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k")}), term.NewFunction("", []term.Term{})}),
							term.NewFunction("payload", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("m")}), term.NewFunction("", []term.Term{term.NewVariable("payloadm")})}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("hmac"), term.NewFunction("", []term.Term{term.NewVariable("k"), term.NewVariable("payloadm")}), term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("hmac", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("k"), term.NewVariable("payloadm")}), term.NewFunction("", []term.Term{term.NewVariable("hmacpayloadm")})}),
						},
					},
					{
						Name: "R_3",
						LHS: []*term.Function{
							term.NewFunction("State0_1", []term.Term{term.NewVariable("m")}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("payload"), term.NewFunction("", []term.Term{term.NewVariable("m")}), term.NewFunction("", []term.Term{term.NewVariable("payloadm")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("payload", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("m")}), term.NewFunction("", []term.Term{term.NewVariable("payloadm")})}),
						},
					},
				},
				false,
			},
			{
				rule.Rule{
					Name: "Y",
					LHS:  []*term.Function{term.NewFunction("State0", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")})},
					Act:  nil,
					RHS: []*term.Function{
						term.NewFunction("State1", []term.Term{
							term.NewFunction("x", []term.Term{term.NewFunction("f", []term.Term{term.NewVariable("a")})}),
							term.NewFunction("y", []term.Term{term.NewFunction("g", []term.Term{term.NewVariable("b")})}),
							term.NewFunction("z", []term.Term{term.NewFunction("h", []term.Term{term.NewVariable("c")})}),
						}),
						term.NewFunction("State2", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
					},
				},
				[]*rule.Rule{
					{
						Name: "Y_prologue",
						LHS:  []*term.Function{term.NewFunction("State0", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")})},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("f"), term.NewFunction("", []term.Term{term.NewVariable("a")}), term.NewFunction("", []term.Term{term.NewVariable("fa")})}),
							term.NewFunction("Fn", []term.Term{term.NewConstant("g"), term.NewFunction("", []term.Term{term.NewVariable("b")}), term.NewFunction("", []term.Term{term.NewVariable("gb")})}),
							term.NewFunction("Fn", []term.Term{term.NewConstant("h"), term.NewFunction("", []term.Term{term.NewVariable("c")}), term.NewFunction("", []term.Term{term.NewVariable("hc")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("State0_0", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
							term.NewFunction("State0_1", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
							term.NewFunction("State0_2", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
							term.NewFunction("State0_3", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
						},
					},
					{
						Name: "Y_epilogue",
						LHS: []*term.Function{
							term.NewFunction("State0_0", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
							term.NewFunction("f", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("a")}), term.NewFunction("", []term.Term{term.NewVariable("fa")})}),
							term.NewFunction("g", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("b")}), term.NewFunction("", []term.Term{term.NewVariable("gb")})}),
							term.NewFunction("h", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("c")}), term.NewFunction("", []term.Term{term.NewVariable("hc")})}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("x"), term.NewFunction("", []term.Term{term.NewVariable("fa")}), term.NewFunction("", []term.Term{term.NewVariable("xfa")})}),
							term.NewFunction("Fn", []term.Term{term.NewConstant("y"), term.NewFunction("", []term.Term{term.NewVariable("gb")}), term.NewFunction("", []term.Term{term.NewVariable("ygb")})}),
							term.NewFunction("Fn", []term.Term{term.NewConstant("z"), term.NewFunction("", []term.Term{term.NewVariable("hc")}), term.NewFunction("", []term.Term{term.NewVariable("zhc")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("State1", []term.Term{term.NewVariable("xfa"), term.NewVariable("ygb"), term.NewVariable("zhc")}),
							term.NewFunction("State2", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
						},
					},
					{
						Name: "Y_0",
						LHS: []*term.Function{
							term.NewFunction("State0_1", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("h"), term.NewFunction("", []term.Term{term.NewVariable("c")}), term.NewFunction("", []term.Term{term.NewVariable("hc")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("h", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("c")}), term.NewFunction("", []term.Term{term.NewVariable("hc")})}),
						},
					},
					{
						Name: "Y_1",
						LHS: []*term.Function{
							term.NewFunction("State0_2", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("g"), term.NewFunction("", []term.Term{term.NewVariable("b")}), term.NewFunction("", []term.Term{term.NewVariable("gb")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("g", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("b")}), term.NewFunction("", []term.Term{term.NewVariable("gb")})}),
						},
					},
					{
						Name: "Y_2",
						LHS: []*term.Function{
							term.NewFunction("State0_3", []term.Term{term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("c")}),
						},
						Act: []*term.Function{
							term.NewFunction("Fn", []term.Term{term.NewConstant("f"), term.NewFunction("", []term.Term{term.NewVariable("a")}), term.NewFunction("", []term.Term{term.NewVariable("fa")})}),
						},
						RHS: []*term.Function{
							term.NewFunction("f", []term.Term{term.NewFunction("", []term.Term{term.NewVariable("a")}), term.NewFunction("", []term.Term{term.NewVariable("fa")})}),
						},
					},
				},
				false,
			},
		}

		for _, test := range translationTests {

			got := rule.Translate(test.src, data.NewSet[string]())
			// if err != nil {
			// 	t.Log(err)
			// }

			if diff := deep.Equal(got, test.dst); diff != nil {
				t.Errorf("wrong translation:\n expected %s\n got      %s\n%s", test.dst, got, diff)
			}

			// if err == nil && test.expectError {
			// 	t.Errorf("expected error but got none")
			// }

			// if err != nil && !test.expectError {
			// 	t.Errorf("not expecting error but got one: %s", err.Error())
			// }

		}
	}
*/
func TestIsStartRuleOf(t *testing.T) {
	t.Parallel()

	rule1 := &rule.Rule{Name: "R_Start"}
	rule2 := &rule.Rule{Name: "R_End"}
	if got := rule.IsStartRuleOf(rule1, rule2); got != false {
		t.Errorf("IsStartRuleOf(%v, %v) = %v, want %v", rule1, rule2, got, false)
	}

	rule1 = &rule.Rule{Name: "R_Start"}
	rule2 = &rule.Rule{Name: "R_0"}
	if got := rule.IsStartRuleOf(rule1, rule2); got != true {
		t.Errorf("IsStartRuleOf(%v, %v) = %v, want %v", rule1, rule2, got, true)
	}

	rule1 = &rule.Rule{Name: "R_NotStart"}
	rule2 = &rule.Rule{Name: "R_0_1"}
	if got := rule.IsStartRuleOf(rule1, rule2); got != false {
		t.Errorf("IsStartRuleOf(%v, %v) = %v, want %v", rule1, rule2, got, false)
	}
}
