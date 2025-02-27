import React, { useEffect, useActionState, } from 'react';

import APIClient from "./api"
// import {useActionState} from 'react-dom';
// import { cvss40score, parseCVSS40 } from './cvss/cvss';

const App: React.FC = () => {
  const [cvssString, setCvssString] = React.useState('CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
  const [score, setScore] = React.useState(0);
  const [error, setError] = React.useState('');

  const handleInputChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {

    try {
      APIClient.parse[''].post({cvss: event.target.value}).then((a) => {

        console.log(a);
      });
    } catch (e) {
      console.log(e);
    }

    setCvssString(event.target.value);
  };

  useEffect(() => {
    calculateScore(cvssString);
  }, [cvssString])


  const [state, formAction, _isPending] = useActionState((prev: {} | null, formData) => {
    console.log(formData.get("cvssString"))

    const a = prev;
    return {}
  }, null)

  const calculateScore = (value: string) => {
    try {
      // Perform CVSS calculation logic here
      const calculatedScore = 1;//cvss40score(parseCVSS40(value));
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
      <form>
        <textarea value={cvssString} name="cvssString" onChange={handleInputChange} />
        {/* <input type='text' value={cvssString}  formAction={formAction} /> */}
        {error && <div>{error}</div>}
        <div>Score: {score}</div>
      </form>
    </div>
  );
};

export default App;