import {
  lookup,
  maxComposed,
  maxComposedEQ3,
  maxSeverityData,
  maxSeverityeq3eq6,
  levels,
} from "./lookup";

type CVSS40 = {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  AT: "N" | "P";
  PR: "N" | "L" | "H";
  UI: "N" | "P" | "A";
  VC: "H" | "L" | "N";
  VI: "H" | "L" | "N";
  VA: "H" | "L" | "N";
  SC: "H" | "L" | "N";
  SI: "S" | "H" | "L" | "N";
  SA: "S" | "H" | "L" | "N";
  E: "X" | "A" | "P" | "U";
  MAV: "X" | "N" | "A" | "L" | "P";
  MAC: "X" | "L" | "H";
  MAT: "X" | "N" | "P";
  MPR: "X" | "N" | "L" | "H";
  MUI: "X" | "N" | "P" | "A";
  MVC: "X" | "H" | "L" | "N";
  MVI: "X" | "H" | "L" | "N";
  MVA: "X" | "H" | "L" | "N";
  MSC: "X" | "H" | "L" | "N";
  MSI: "X" | "S" | "H" | "L" | "N";
  MSA: "X" | "S" | "H" | "L" | "N";
  CR: "X" | "H" | "M" | "L";
  IR: "X" | "H" | "M" | "L";
  AR: "X" | "H" | "M" | "L";
  S: "X" | "N" | "P";
  AU: "X" | "N" | "Y";
  R: "X" | "A" | "U" | "I";
  V: "X" | "D" | "C";
  RE: "X" | "L" | "M" | "H";
  U: "X" | "Clear" | "Green" | "Amber" | "Red";
};

export function parseCVSS40(cvss40: string, skipPrefix = false): CVSS40 {
  cvss40 = cvss40.trim()

  if (!skipPrefix) {
    if (!cvss40.startsWith("CVSS:4.0")) {
      throw 'Is not a valid CVSS4.0 string'
    }
    cvss40 = cvss40.slice("CVSS:4.0".length + 1)
  } else {
    cvss40 = cvss40.slice(0, -1)
  }

  const metricsMap = new Map()
  const rawMetrics = cvss40.split("/")

  for (let rawMetric of rawMetrics) {
    const metricAndValue = rawMetric.split(":")
    if (metricAndValue.length != 2) {
      
      throw `Invalid metric ${rawMetric} ${metricAndValue}`
    } else {
      if (metricsMap.has(metricAndValue[0])) {
        throw `Metric ${metricAndValue[0]} is already present`
      }

      metricsMap.set(metricAndValue[0], metricAndValue[1])
    }
  }

  const extractValueMetric = function <T>(metric: string, cvssStr: string, constraint: string[]): T {
    return extractValueMetricFromMap(metric, cvssStr, metricsMap, constraint)
  }

  const extractValueMetricOptional = function <T>(metric: string, cvssStr: string, defaultValue: T, constraint: string[]): T {
    return extractValueMetricOptionalFromMap(metric, cvssStr, defaultValue, metricsMap, constraint)
  }

  const parsedCvss: CVSS40 = {
    AV: extractValueMetric("AV", cvss40, ["N", "A", "L", "P"]),
    AC: extractValueMetric("AC", cvss40, ["L", "H"]),
    AT: extractValueMetric("AT", cvss40, ["N", "P"]),
    PR: extractValueMetric("PR", cvss40, ["N", "L", "H"]),
    UI: extractValueMetric("UI", cvss40, ["N", "P", "A"]),
    VC: extractValueMetric("VC", cvss40, ["H", "L", "N"]),
    VI: extractValueMetric("VI", cvss40, ["H", "L", "N"]),
    VA: extractValueMetric("VA", cvss40, ["H", "L", "N"]),
    SC: extractValueMetric("SC", cvss40, ["H", "L", "N"]),
    SI: extractValueMetric("SI", cvss40, ["S", "H", "L", "N"]),
    SA: extractValueMetric("SA", cvss40, ["S", "H", "L", "N"]),
    E: extractValueMetricOptional("E", cvss40, "A", ["X", "A", "P", "U"]),
    MAV: extractValueMetricOptional("MAV", cvss40, "X", ["X", "N", "A", "L", "P"]),
    MAC: extractValueMetricOptional("MAC", cvss40, "X", ["X", "L", "H"]),
    MAT: extractValueMetricOptional("MAT", cvss40, "X", ["X", "N", "P"]),
    MPR: extractValueMetricOptional("MPR", cvss40, "X", ["X", "N", "L", "H"]),
    MUI: extractValueMetricOptional("MUI", cvss40, "X", ["X", "N", "P", "A"]),
    MVC: extractValueMetricOptional("MVC", cvss40, "X", ["X", "H", "L", "N"]),
    MVI: extractValueMetricOptional("MVI", cvss40, "X", ["X", "H", "L", "N"]),
    MVA: extractValueMetricOptional("MVA", cvss40, "X", ["X", "H", "L", "N"]),
    MSC: extractValueMetricOptional("MSC", cvss40, "X", ["X", "H", "L", "N"]),
    MSA: extractValueMetricOptional("MSA", cvss40, "X", ["X", "S", "H", "L", "N"]),
    MSI: extractValueMetricOptional("MSI", cvss40, "X", ["X", "S", "H", "L", "N"]),
    CR: extractValueMetricOptional("CR", cvss40, "H", ["X", "H", "M", "L"]),
    IR: extractValueMetricOptional("IR", cvss40, "H", ["X", "H", "M", "L"]),
    AR: extractValueMetricOptional("AR", cvss40, "H", ["X", "H", "M", "L"]),
    S: extractValueMetricOptional("S", cvss40, "X", ["X", "N", "P"]),
    AU: extractValueMetricOptional("AU", cvss40, "X", ["X", "N", "Y"]),
    R: extractValueMetricOptional("R", cvss40, "X", ["X", "A", "U", "I"]),
    V: extractValueMetricOptional("V", cvss40, "X", ["X", "D", "C"]),
    RE: extractValueMetricOptional("RE", cvss40, "X", ["X", "L", "M", "H"]),
    U: extractValueMetricOptional("U", cvss40, "X", ["X", "Clear", "Green", "Amber", "Red"]),
  }

  if (metricsMap.size > 0) {
    let e = ''
    for (let a in metricsMap.keys()) {
      e += a
    }
    throw `CVSS string contains some invalid metrics '${e}'`
  }

  return parsedCvss
}

export function cvss40score(cvss: CVSS40) {
  const macroVectorResult: number[] = macroVector(cvss)

  const defaultMetrics = ["VC", "VI", "VA", "SC", "SI", "SA"]
  type MetricType = "VC" | "VI" | "VA" | "SC" | "SI" | "SA"

  if (defaultMetrics.every((metric) => cvss[metric as MetricType] == "N")) {
    return 0.0;
  }

  const [eq1, eq2, eq3, eq4, eq5, eq6] = macroVectorResult;

  const next_lower_macro = [
    lookup([eq1 + 1, eq2, eq3, eq4, eq5, eq6]),
    lookup([eq1, eq2 + 1, eq3, eq4, eq5, eq6]),
    calcScoreEq3eq6NextLowerMacro(macroVectorResult),
    lookup([eq1, eq2, eq3, eq4 + 1, eq5, eq6]),
    lookup([eq1, eq2, eq3, eq4, eq5 + 1, eq6]),
  ];

  const max_vectors = calcMaxVectors(macroVectorResult);

  const current_severities = getSeverities(cvss, max_vectors);

  let value = lookup(macroVectorResult);

  if (value === undefined) throw "Can'lookup value";

  const mean_distance = calcMeanDistance(
    value,
    next_lower_macro,
    macroVectorResult,
    current_severities,
    eq6,
  );

  // 3. The score of the vector is the score of the MacroVector
  //    (i.e. the score of the highest severity vector) minus the mean
  //    distance so computed. This score is rounded to one decimal place.

  value -= mean_distance;
  if (value < 0) {
    value = 0.0;
  }
  if (value > 10) {
    value = 10.0;
  }
  return Math.round(value * 10) / 10;
}

function calcMeanDistance(
  value: number,
  nextLowerMacro: (number | undefined)[],
  macroVectorResult: number[],
  currentSeverities: number[] | undefined,
  eq6: number,
): number {
  let nExistingLower = 0;

  const normalizedSeverities = [0, 0, 0, 0, 0].map((norm_serv, i) => {
    if (nextLowerMacro[i] !== undefined) {
      const available_distance_eqi = value - nextLowerMacro[i];
      nExistingLower = nExistingLower + 1;
      if (i == 4) {
        return 0;
      }
      const eqi = macroVectorResult[i];
      const maxSeverity =
        (i != 2 ? maxSeverityData[i][eqi] : maxSeverityeq3eq6[eqi][eq6]) * 0.1; // step is 0.1
      const percentToNextEqiSeverity =
        currentSeverities === undefined
          ? 0
          : currentSeverities[i] / maxSeverity;
      return available_distance_eqi * percentToNextEqiSeverity;
    }
    return norm_serv;
  });

  const meanDistance =
    nExistingLower == 0
      ? 0
      : normalizedSeverities.reduce((s, c) => s + c, 0) / nExistingLower;
  return meanDistance;
}

type IsOfType<T, U> = T extends U ? T : never;

function isOfType<A>(input: string): input is IsOfType<typeof input, A> {
  return (input as A) !== undefined;
}

function calcMaxVectors([eq1, eq2, eq3, eq4, eq5, eq6]: number[]): string[] {
  const eq1_maxes = maxComposed[0][eq1];
  const eq2_maxes = maxComposed[1][eq2];
  const eq3_eq6_maxes = maxComposedEQ3[eq3][eq6];
  const eq4_maxes = maxComposed[3][eq4];
  const eq5_maxes = maxComposed[4][eq5];

  const max_vectors = [];
  for (let eq1_max of eq1_maxes) {
    for (let eq2_max of eq2_maxes) {
      for (let eq3_eq6_max of eq3_eq6_maxes) {
        for (let eq4_max of eq4_maxes) {
          for (let eq5max of eq5_maxes) {
            max_vectors.push(
              eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max,
            );
          }
        }
      }
    }
  }
  return max_vectors;
}


function getSeverities(
  cvss: CVSS40,
  max_vectors: string[],
): number[] | undefined {
  // Find the max vector to use i.e. one in the combination of all the highests
  // that is greater or equal (severity distance) than the to-be scored vector.

  for (let i = 0; i < max_vectors.length; i++) {
    const max_vector: CVSS40 = parseCVSS40(max_vectors[i], true);

    // calculate distances
    const AV = levels["AV"][cvss.AV] - levels["AV"][max_vector.AV];
    const PR = levels["PR"][cvss.PR] - levels["PR"][max_vector.PR];
    const UI = levels["UI"][cvss.UI] - levels["UI"][max_vector.UI];

    const AC = levels["AC"][cvss.AC] - levels["AC"][max_vector.AC];
    const AT = levels["AT"][cvss.AT] - levels["AT"][max_vector.AT];

    const VC = levels["VC"][cvss.VC] - levels["VC"][max_vector.VC];
    const VI = levels["VI"][cvss.VI] - levels["VI"][max_vector.VI];
    const VA = levels["VA"][cvss.VA] - levels["VA"][max_vector.VA];

    const SC = levels["SC"][cvss.SC] - levels["SC"][max_vector.SC];
    const SI = levels["SI"][cvss.SI] - levels["SI"][max_vector.SI];
    const SA = levels["SA"][cvss.SA] - levels["SA"][max_vector.SA];

    const CR = levels["CR"][cvss.CR] - levels["CR"][max_vector.CR];
    const IR = levels["IR"][cvss.IR] - levels["IR"][max_vector.IR];
    const AR = levels["AR"][cvss.AR] - levels["AR"][max_vector.AR];

    // if any is less than zero this is not the right max
    if (
      [AV, PR, UI, AC, AT, VC, VI, VA, SC, SI, SA, CR, IR, AR].some(
        (met) => met < 0,
      )
    ) {
      continue;
    }
    // if multiple maxes exist to reach it it is enough the first one
    return [
      AV + PR + UI, //EQ1
      AC + AT, //EQ2
      VC + VI + VA + CR + IR + AR, //EQ3EQ6
      SC + SI + SA, // EQ4
      0,
    ];
  }
}

function calcScoreEq3eq6NextLowerMacro(eq: number[]): number | undefined {
  const [eq1, eq2, eq3, eq4, eq5, eq6] = eq;

  let eq3eq6NextLowerMacro;
  if (eq3 == 1 && eq6 == 1) {
    // 11 --> 21
    eq3eq6NextLowerMacro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6];
  } else if (eq3 == 0 && eq6 == 1) {
    // 01 --> 11
    eq3eq6NextLowerMacro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6];
  } else if (eq3 == 1 && eq6 == 0) {
    // 10 --> 11
    eq3eq6NextLowerMacro = [eq1, eq2, eq3, eq4, eq5, eq6 + 1];
  } else if (eq3 == 0 && eq6 == 0) {
    // 00 --> 01
    // 00 --> 10

    const scoreEq3eq6NextLowerL = lookup([eq1, eq2, eq3, eq4, eq5, eq6 + 1]);
    const scoreEq3eq6NextLowerR = lookup([eq1, eq2, eq3 + 1, eq4, eq5, eq6]);

    if (
      scoreEq3eq6NextLowerL === undefined ||
      scoreEq3eq6NextLowerR === undefined
    )
      return undefined;

    return Math.max(scoreEq3eq6NextLowerL, scoreEq3eq6NextLowerR);
  } else {
    // 21 --> 32 (do not exist)
    eq3eq6NextLowerMacro = [eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1];
  }

  return lookup(eq3eq6NextLowerMacro);
}

function extractValueMetricFromMap<T>(metric: string, cvssStr: string, metrics: Map<string, string>, constraint: string[]): T {
  // check if there is an overwriting M-metric for this metric.
  if (metrics.has(`M${metric}`)) {
    const r = metrics.get(`M${metric}`)!
    metrics.delete(metric)
    if (isOfType(r) && constraint.includes(r)) {
      return r as T;
    } else {
      throw `Metric '${metric}' has wrong value ${r}`;
    }
  }

  if (metrics.has(metric)) {
    const r = metrics.get(metric)!
    metrics.delete(metric)
    if (isOfType(r) && constraint.includes(r)) {
      return r as T;
    } else {
      throw `Metric '${metric}' has wrong value ${r}`;
    }
  }

  throw `Metric '${metric}' is required`;
}

function extractValueMetricOptionalFromMap<T>(metric: string, cvssStr: string, defaultValue: T, metrics: Map<string, string>, constraint: string[]): T {
  // check if there is an overwriting M-metric for this metric.
  if (metrics.has(`M${metric}`)) {
    const r = metrics.get(`M${metric}`)!
    metrics.delete(metric)
    if (isOfType(r) && constraint.includes(r)) {
      return r as T;
    } else {
      throw `Metric '${metric}' has wrong value ${r}`;
    }
  }

  if (metrics.has(metric)) {
    const r = metrics.get(metric)!
    metrics.delete(metric)
    if (isOfType(r) && constraint.includes(r)) {
      return r as T;
    } else {
      throw `Metric '${metric}' has wrong value ${r}`;
    }
  }

  return defaultValue;
}

export function macroVector(cvss: CVSS40): number[] {
  // EQ1: 0-AV:N and PR:N and UI:N
  //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  //      2-AV:P or not(AV:N or PR:N or UI:N)

  const eq: number[] = [];

  if (cvss.AV == "N" && cvss.PR == "N" && cvss.UI == "N") {
    eq[0] = 0;
  } else if (
    (cvss.AV == "N" || cvss.PR == "N" || cvss.UI == "N") &&
    !(cvss.AV == "N" && cvss.PR == "N" && cvss.UI == "N") &&
    !(cvss.AV == "P")
  ) {
    eq[0] = 1;
  } else if (
    cvss.AV == "P" ||
    !(cvss.AV == "N" || cvss.PR == "N" || cvss.UI == "N")
  ) {
    eq[0] = 2;
  }

  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))

  if (cvss.AC == "L" && cvss.AT == "N") {
    eq[1] = 0;
  } else if (!(cvss.AC == "L" && cvss.AT == "N")) {
    eq[1] = 1;
  }

  // EQ3: 0-(VC:H and VI:H)
  //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
  //      2-not (VC:H or VI:H or VA:H)
  if (cvss.VC == "H" && cvss.VI == "H") {
    eq[2] = 0;
  } else if (
    !(cvss.VC == "H" && cvss.VI == "H") &&
    (cvss.VC == "H" || cvss.VI == "H" || cvss.VA == "H")
  ) {
    eq[2] = 1;
  } else if (!(cvss.VC == "H" || cvss.VI == "H" || cvss.VA == "H")) {
    eq[2] = 2;
  }

  // EQ4: 0-(MSI:S or MSA:S)
  //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

  if (cvss.MSI == "S" || cvss.MSA == "S") {
    eq[3] = 0;
  } else if (
    // this one is redundant -> !(cvss.MSI == "S" || cvss.MSA == "S") &&
    cvss.SC == "H" ||
    cvss.SI == "H" ||
    cvss.SA == "H"
  ) {
    eq[3] = 1;
  } else {
    // this one is redundant -> if (!(cvss.MSI == "S" || cvss.MSA == "S") &&
    //!((cvss.SC == "H" || cvss.SI == "H" || cvss.SA == "H")))
    eq[3] = 2;
  }

  // EQ5: 0-E:A
  //      1-E:P
  //      2-E:U

  if (cvss.E == "A") {
    eq[4] = 0;
  } else if (cvss.E == "P") {
    eq[4] = 1;
  } else if (cvss.E == "U") {
    eq[4] = 2;
  }

  // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

  if (
    (cvss.CR == "H" && cvss.VC == "H") ||
    (cvss.IR == "H" && cvss.VI == "H") ||
    (cvss.AR == "H" && cvss.VA == "H")
  ) {
    eq[5] = 0;
  } else if (
    !(
      (cvss.CR == "H" && cvss.VC == "H") ||
      (cvss.IR == "H" && cvss.VI == "H") ||
      (cvss.AR == "H" && cvss.VA == "H")
    )
  ) {
    eq[5] = 1;
  }

  return eq;
}
