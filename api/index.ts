import {parseCVSS40} from "cvss-lib";
import { Elysia, t } from 'elysia'
import { swagger } from '@elysiajs/swagger'
import { cors } from '@elysiajs/cors'

const app = new Elysia()
  .use(swagger())
  .use(cors())
	.get('/', () => 'Hello Elysia')
	.post('/parse/', ({body}) => {
		return parseCVSS40(body.cvss);
	}, {
		body: t.Object({
			cvss: t.String()
		})
  })
	.listen(3000, ({ hostname, port }) => {
		console.log(
			`🦊 Elysia is running at ${hostname}:${port}`
		)
	});

export type CVSSApi = typeof app;
