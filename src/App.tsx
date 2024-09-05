import React, { useEffect } from 'react';
import { cvss40score, parseCVSS40 } from './cvss/cvss';

const App: React.FC = () => {
  const [cvssString, setCvssString] = React.useState('CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
  const [score, setScore] = React.useState(0);
  const [error, setError] = React.useState('');

  const handleInputChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setCvssString(event.target.value);
  };

  useEffect(() => {
    calculateScore(cvssString);
  }, [cvssString])

  const calculateScore = (value: string) => {
    try {
      // Perform CVSS calculation logic here
      const calculatedScore = cvss40score(parseCVSS40(value));
      setScore(calculatedScore);
      setError('');
    } catch (error) {
      setScore(0);
      setError("" + error);
    }
  };

  return (
    <div>
      <h1>CVSS4.0 Calculator Demo</h1>
      <textarea value={cvssString} onChange={handleInputChange} />
      {error && <div>{error}</div>}
      <div>Score: {score}</div>
    </div>
  );
};

export default App;