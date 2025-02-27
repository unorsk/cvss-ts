import type { CVSSApi } from 'api';
import { treaty } from '@elysiajs/eden';

const APIClient = treaty<CVSSApi>('http://localhost:3000') 

export default APIClient