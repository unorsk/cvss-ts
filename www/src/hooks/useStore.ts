import { create } from 'zustand'

export interface CVSSState {
  cvss: string;
  score?: number;
  updateCVSS: (cvss: string) => void;
  updateScore: (score: number) => void;
}

export const useStore = create<CVSSState>((set) => ({
  cvss: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  score: undefined,
  updateCVSS: (cvss) => set((state) => ({ cvss: cvss })),
  updateScore: (score) => set((state) => ({ score: score })),
}))
