// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

export const maxComposedEQ3: string[][][] = [
	[ ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] ],
	[ ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] ],
	[ [], ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] ],
]

export const maxComposed: string[][][] = [
	// EQ1
	[
		 ["AV:N/PR:N/UI:N/"],
		 ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
		 ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
	],
	// EQ2
	[
		 ["AC:L/AT:N/"],
		 ["AC:H/AT:N/", "AC:L/AT:P/"]
	],
	[],// EQ3+EQ6
	// [
	// 	[ ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] ],
	// 	[ ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] ],
	// 	[ [], ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] ],
	// ],
	
	// EQ4
	[
		["SC:H/SI:S/SA:S/"],
		["SC:H/SI:H/SA:H/"],
		["SC:L/SI:L/SA:L/"]

	],
	// EQ5
	[
		["E:A/"],
		["E:P/"],
		["E:U/"],
	],
]