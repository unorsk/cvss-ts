import React, { useEffect } from 'react';

import APIClient from "./api/api"
import { useStore, type CVSSState } from './hooks/useStore';

const App: React.FC = () => {
  const { cvss, updateCVSS, updateScore } = useStore<CVSSState>(state => state);
  const [error, setError] = React.useState<string | undefined>(undefined);

  useEffect(() => {
    recalculateScore(cvss);
  }, [cvss])

  const handleInputChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    updateCVSS(event.target.value);
  }

  const recalculateScore = async (cvssString: string) => {
    setError(undefined);
    updateCVSS(cvssString);

    const { data: score, error } = await APIClient.score.post({ cvss: cvssString });

    if (score) {
      updateScore(score)
    }
    if (error) {
      setError(error.value as string)
    }
  }

  return (
    <div>
      <h1>CVSS4.0 Calculator Demo</h1>
      <form>
        <textarea value={cvss} name="cvssString" onChange={handleInputChange} />
        {error && <div>{error}</div>}
        {!error && <ScoreComponent />}
      </form>
    </div>
  );
};

const ScoreComponent: React.FC = () => {
  const score = useStore((state) => state.score);
  return <div>{score}</div>;
}

export default App;