import { lookup } from "./lookup"
import { maxComposed, maxComposedEQ3 } from "./max_composed"
import { maxSeverity as maxSeverityData, maxSeverityeq3eq6 } from "./max_severity"

const AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
const AC_levels = {'L': 0.0, 'H': 0.1}
const AT_levels = {'N': 0.0, 'P': 0.1}
const PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
const UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}
const VC_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
const VI_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
const VA_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
const SC_levels = {'H': 0.1, 'L': 0.2, 'N': 0.3}
const SI_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3} // TODO S doesn't exist on SI according to the spec
const SA_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3} // TODO S doesn't exist on SI according to the spec
const CR_levels = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2} // TODO: need X, setting it to 0 idk 
const IR_levels = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2} // TODO: need X, setting it to 0 idk 
const AR_levels = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2} // TODO: need X, setting it to 0 idk 
const E_levels = {'U': 0.2, 'P': 0.1, 'A': 0} // TODO: not needed :)


type CVSS40 = {
  AV: 'N' | 'A' | 'L' | 'P',
  AC: 'L' | 'H',
  AT: 'N' | 'P',  
  PR: 'N' | 'L' | 'H',
  UI: 'N' | 'P' | 'A',
  VC: 'H' | 'L' | 'N',
  VI: 'H' | 'L' | 'N',
  VA: 'H' | 'L' | 'N',
  SC: 'H' | 'L' | 'N',
  SI: 'H' | 'L' | 'N',
  SA: 'H' | 'L' | 'N',
  E?: 'X' | 'A' | 'P' | 'U',
  MAV?: 'X' | 'N' | 'A' | 'L' | 'P',
  MAC?: 'X' | 'L' | 'H',
  MAT?: 'X' | 'N' | 'P',
  MPR?: 'X' | 'N' | 'L' | 'H',
  MUI?: 'X' | 'N' | 'P' | 'A',
  MVC?: 'X' | 'H' | 'L' | 'N',
  MVI?: 'X' | 'H' | 'L' | 'N',
  MVA?: 'X' | 'H' | 'L' | 'N',
  MSC?: 'X' | 'H' | 'L' | 'N',
  MSI?: 'X' | 'S' | 'H' | 'L' | 'N',
  MSA?: 'X' | 'S' | 'H' | 'L' | 'N',
  CR?: 'X' | 'H' | 'M' | 'L',
  IR?: 'X' | 'H' | 'M' | 'L',
  AR?: 'X' | 'H' | 'M' | 'L',
  S?: 'X' | 'N' | 'P',
  AU?: 'X' | 'N' | 'Y',
  R?: 'X' | 'A' | 'U' | 'I',
  V?: 'X' | 'D' | 'C',
  RE?: 'X' | 'L' | 'M' | 'H',
  U?: 'X' | 'Clear' | 'Green' | 'Amber' | 'Red',
}

type MetricType = "VC" | "VI" | "VA" | "SC" | "SI" | "SA";

export function parseCVSS40(cvss40: string): CVSS40 {
    cvss40 = cvss40.startsWith("CVSS:4.0") ? cvss40.slice("CVSS:4.0".length) : cvss40;

    return {
        AV: extractValueMetric("AV", cvss40),
        AC: extractValueMetric("AC", cvss40),
        AT: extractValueMetric("AT", cvss40),
        PR: extractValueMetric("PR", cvss40),
        UI: extractValueMetric("UI", cvss40),
        VC: extractValueMetric("VC", cvss40),
        VI: extractValueMetric("VI", cvss40),
        VA: extractValueMetric("VA", cvss40),
        SC: extractValueMetric("SC", cvss40),
        SI: extractValueMetric("SI", cvss40),
        SA: extractValueMetric("SA", cvss40),
        E: extractValueMetric("E", cvss40) ?? 'A',//todo even if X
        MAV: extractValueMetric("MAV", cvss40) ?? 'X',
        MAC: extractValueMetric("MAC", cvss40) ?? 'X',
        MAT: extractValueMetric("MAT", cvss40) ?? 'X',
        MPR: extractValueMetric("MPR", cvss40) ?? 'X',
        MUI: extractValueMetric("MUI", cvss40) ?? 'X',
        MVC: extractValueMetric("MVC", cvss40) ?? 'X',
        MVI: extractValueMetric("MVI", cvss40) ?? 'X',
        MVA: extractValueMetric("MVA", cvss40) ?? 'X',
        MSC: extractValueMetric("MSC", cvss40) ?? 'X',
        MSA: extractValueMetric("MSA", cvss40) ?? 'X',
        MSI: extractValueMetric("MSI", cvss40) ?? 'X',
        CR: extractValueMetric("CR", cvss40) ?? 'H',//todo even if X
        IR: extractValueMetric("IR", cvss40) ?? 'H',//todo even if X
        AR: extractValueMetric("AR", cvss40) ?? 'H',//todo even if X
        S: extractValueMetric("S", cvss40) ?? 'X',
        AU: extractValueMetric("AU", cvss40) ?? 'X',
        R: extractValueMetric("R", cvss40) ?? 'X',
        V: extractValueMetric("V", cvss40) ?? 'X',
        RE: extractValueMetric("RE", cvss40) ?? 'X',
        U: extractValueMetric("U", cvss40) ?? 'X',
    }
}

function calcMaxVectors([eq1, eq2, eq3, eq4, eq5, eq6]: number[]) {

    const eq1_maxes = maxComposed[0][eq1]
    const eq2_maxes = maxComposed[1][eq2]
    const eq3_eq6_maxes = maxComposedEQ3[eq3][eq6] // macroVectorResult[5] -> eq6 because of JS :)
    const eq4_maxes = maxComposed[3][eq4]
    const eq5_maxes = maxComposed[4][eq5]

    const max_vectors = []
    for (let eq1_max of eq1_maxes) {
        for (let eq2_max of eq2_maxes) {
            for (let eq3_eq6_max of eq3_eq6_maxes) {
                for (let eq4_max of eq4_maxes) {
                    for (let eq5max of eq5_maxes) {
                        max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)
                    }
                }
            }
        }
    }
    return max_vectors
  }

export function cvss40score (macroVectorResult: number[], cvss: CVSS40) {
  if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => cvss[metric as MetricType] == "N")) {
      return 0.0
  }

  const [eq1, eq2, eq3, eq4, eq5, eq6] = macroVectorResult

  const next_lower_macro = [
    lookup[[eq1 + 1, eq2, eq3, eq4, eq5, eq6].join("")],
    lookup[[eq1, eq2 + 1, eq3, eq4, eq5, eq6].join("")],
    calc_score_eq3eq6_next_lower_macro(macroVectorResult),
    lookup[[eq1, eq2, eq3, eq4 + 1, eq5, eq6].join("")],
    lookup[[eq1, eq2, eq3, eq4, eq5 + 1, eq6].join("")],
  ]

  const max_vectors = calcMaxVectors(macroVectorResult)

  const current_severities = getSeverities(cvss, max_vectors)

  let value = lookup[macroVectorResult.join("")]

  const mean_distance = calcMeanDistance(value, next_lower_macro, macroVectorResult, current_severities, eq6)

  // 3. The score of the vector is the score of the MacroVector
  //    (i.e. the score of the highest severity vector) minus the mean
  //    distance so computed. This score is rounded to one decimal place.
  value -= mean_distance;
  if (value < 0) {
      value = 0.0
  }
  if (value > 10) {
      value = 10.0
  }
  return Math.round(value * 10) / 10
}

function calcMeanDistance(value: number, next_lower_macro: number[], macroVectorResult: number[], current_severities: number[], eq6: number) {
    let n_existing_lower = 0

    const normalized_severity = [ 0, 0, 0, 0, 0 ].map((norm_serv, i) => {
        const available_distance_eqi = value - next_lower_macro[i]
        if (!isNaN(available_distance_eqi)) {
            n_existing_lower = n_existing_lower + 1
            if (i == 4) {
                return 0
            }
            const eqi = macroVectorResult[i]
            const maxSeverity = (i != 2 ? maxSeverityData[i][eqi] : maxSeverityeq3eq6[eqi][eq6]) * 0.1// step is 0.1
            const percent_to_next_eqi_severity = current_severities[i] / maxSeverity
            return available_distance_eqi * percent_to_next_eqi_severity
        }
        return norm_serv
    })

    const mean_distance = n_existing_lower == 0 ? 0 : normalized_severity.reduce((s, c) => s+c, 0) / n_existing_lower
    return mean_distance
  }

function getSeverities(cvss: CVSS40, max_vectors: string[] ) {
    // Find the max vector to use i.e. one in the combination of all the highests
    // that is greater or equal (severity distance) than the to-be scored vector.
    let severity_distance_AV = 0
    let severity_distance_PR = 0
    let severity_distance_UI = 0
    let severity_distance_AC = 0
    let severity_distance_AT = 0
    let severity_distance_VC = 0
    let severity_distance_VI = 0
    let severity_distance_VA = 0
    let severity_distance_SC = 0
    let severity_distance_SI = 0
    let severity_distance_SA = 0
    let severity_distance_CR = 0
    let severity_distance_IR = 0
    let severity_distance_AR = 0

    for (let i = 0; i < max_vectors.length; i++) {
        const max_vector: CVSS40 = parseCVSS40(max_vectors[i]);

        severity_distance_AV = AV_levels[cvss.AV] - AV_levels[max_vector.AV]
        severity_distance_PR = PR_levels[cvss.PR] - PR_levels[max_vector.PR]
        severity_distance_UI = UI_levels[cvss.UI] - UI_levels[max_vector.UI]

        severity_distance_AC = AC_levels[cvss.AC] - AC_levels[max_vector.AC]
        severity_distance_AT = AT_levels[cvss.AT] - AT_levels[max_vector.AT]

        severity_distance_VC = VC_levels[cvss.VC] - VC_levels[max_vector.VC]
        severity_distance_VI = VI_levels[cvss.VI] - VI_levels[max_vector.VI]
        severity_distance_VA = VA_levels[cvss.VA] - VA_levels[max_vector.VA]

        severity_distance_SC = SC_levels[cvss.SC] - SC_levels[max_vector.SC]
        severity_distance_SI = SI_levels[cvss.SI] - SI_levels[max_vector.SI]
        severity_distance_SA = SA_levels[cvss.SA] - SA_levels[max_vector.SA]

        severity_distance_CR = CR_levels[cvss.CR] - CR_levels[max_vector.CR]
        severity_distance_IR = IR_levels[cvss.IR] - IR_levels[max_vector.IR]
        severity_distance_AR = AR_levels[cvss.AR] - AR_levels[max_vector.AR]


        // if any is less than zero this is not the right max
        if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) {
            continue
        }
        // if multiple maxes exist to reach it it is enough the first one
        break
    }

    return [
        severity_distance_AV + severity_distance_PR + severity_distance_UI, //EQ1
        severity_distance_AC + severity_distance_AT, //EQ2
        severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR, //EQ3EQ6
        severity_distance_SC + severity_distance_SI + severity_distance_SA, // EQ4
        0, // EQ5 TODO THIS IS ACTUALLY UNUSED
    ]
}

function calc_score_eq3eq6_next_lower_macro(eq: number[]): number {
    const [eq1, eq2, eq3, eq4, eq5, eq6] = eq
    
    let eq3eq6_next_lower_macro
    if (eq3 == 1 && eq6 == 1) {
        // 11 --> 21
        eq3eq6_next_lower_macro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6]
    } else if (eq3 == 0 && eq6 == 1) {
        // 01 --> 11
        eq3eq6_next_lower_macro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6]
    } else if (eq3 == 1 && eq6 == 0) {
        // 10 --> 11
        eq3eq6_next_lower_macro = [eq1, eq2, eq3, eq4, eq5, eq6 + 1]
    } else if (eq3 == 0 && eq6 == 0) {
        // 00 --> 01
        // 00 --> 10
        const eq3eq6_next_lower_macro_left = [eq1, eq2, eq3, eq4, eq5, eq6 + 1].join("")
        const eq3eq6_next_lower_macro_right = [eq1, eq2, eq3 + 1, eq4, eq5, eq6].join("")

        const score_eq3eq6_next_lower_macro_left = lookup[eq3eq6_next_lower_macro_left]
        const score_eq3eq6_next_lower_macro_right = lookup[eq3eq6_next_lower_macro_right]

        if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) {
            // score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
            return score_eq3eq6_next_lower_macro_left
        } else {
            // score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
            return score_eq3eq6_next_lower_macro_right
        }

    } else {
        // 21 --> 32 (do not exist)
        eq3eq6_next_lower_macro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]
    }

    if (!(eq3 == 0 && eq6 == 0)) {
        // score_eq3eq6_next_lower_macro = lookup[eq3eq6_next_lower_macro.join("")]
        return lookup[eq3eq6_next_lower_macro.join("")]
    }

    return 0; //TODO: well, otherwise it's undefined...
}

function extractValueMetric(metric: string, cvssStr: string) {
    const cvssArray = cvssStr.split('/')

    // check if there is an overwriting M-metric for this metric.
    const mIndex = cvssArray.findIndex((e) => e.startsWith('M'+metric + ":"))
    if (mIndex >= 0) {
        return cvssArray[mIndex].split(":")[1]
    }

    const i = cvssArray.findIndex((e) => e.startsWith(metric + ":"))
    if (i >= 0) {
        return cvssArray[i].split(":")[1]
    }

}

export function macroVector(cvss: CVSS40): number[] {
  // EQ1: 0-AV:N and PR:N and UI:N
  //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  //      2-AV:P or not(AV:N or PR:N or UI:N)

  const eq: number[] = [];

  if (cvss.AV == "N" && cvss.PR == "N" && cvss.UI == "N") {
      eq[0] = 0
  } else if ((cvss.AV == "N" || cvss.PR == "N" || cvss.UI == "N")
      && !(cvss.AV == "N" && cvss.PR == "N" && cvss.UI == "N")
      && !(cvss.AV == "P")) {
      eq[0] = 1
  } else if (cvss.AV == "P"
      || !(cvss.AV == "N" || cvss.PR == "N" || cvss.UI == "N")) {
      eq[0] = 2
  }

  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))

  if (cvss.AC == "L" && cvss.AT == "N") {
      eq[1] = 0
  } else if (!(cvss.AC == "L" && cvss.AT == "N")) {
      eq[1] = 1
  }

  // EQ3: 0-(VC:H and VI:H)
  //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
  //      2-not (VC:H or VI:H or VA:H)
  if (cvss.VC == "H" && cvss.VI == "H") {
      eq[2] = 0
  } else if (!(cvss.VC == "H" && cvss.VI == "H")
      && (cvss.VC == "H" || cvss.VI == "H" || cvss.VA == "H")) {
      eq[2] = 1
  } else if (!(cvss.VC == "H" || cvss.VI == "H" || cvss.VA == "H")) {
      eq[2] = 2
  }

  // EQ4: 0-(MSI:S or MSA:S)
  //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

  if (cvss.MSI == "S" || cvss.MSA == "S") {
      eq[3] = 0
  } else if (// this one is redundant -> !(cvss.MSI == "S" || cvss.MSA == "S") &&
      (cvss.SC == "H" || cvss.SI == "H" || cvss.SA == "H")) {
      eq[3] = 1
  } else { // this one is redundant -> if (!(cvss.MSI == "S" || cvss.MSA == "S") &&
      //!((cvss.SC == "H" || cvss.SI == "H" || cvss.SA == "H")))
      eq[3] = 2
  }

  // EQ5: 0-E:A
  //      1-E:P
  //      2-E:U

  if (cvss.E == "A") {
      eq[4] = 0
  } else if (cvss.E == "P") {
      eq[4] = 1
  } else if (cvss.E == "U") {
      eq[4] = 2
  }

  // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

  if ((cvss.CR == "H" && cvss.VC == "H")
      || (cvss.IR == "H" && cvss.VI == "H")
      || (cvss.AR == "H" && cvss.VA == "H")) {
      eq[5] = 0
  } else if (!((cvss.CR == "H" && cvss.VC == "H")
      || (cvss.IR == "H" && cvss.VI == "H")
      || (cvss.AR == "H" && cvss.VA == "H"))) {
      eq[5] = 1
  }

  return eq
}
