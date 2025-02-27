import { parseCVSS40, scoreCVSS40 } from "cvss-lib";
import { Elysia, t } from 'elysia'
import { swagger } from '@elysiajs/swagger'
import { cors } from '@elysiajs/cors'

const app = new Elysia()
	.use(swagger({
		path: '/v2/swagger',
		documentation: {
			info: {
				title: 'CVSS Api Documentation',
				version: '1.0.0'
			}
		}
	}))
	.use(cors())
	.get('/', () => 'Hello')
	.post('/score', ({ body, error }) => {
		try {
			return scoreCVSS40(parseCVSS40(body.cvss));
		} catch (e) {
			return error(400, e);
		}
	}, {
		body: t.Object({
			cvss: t.String()
		})
	})
	.post('/parse', ({ body }) => {
		return parseCVSS40(body.cvss);
	}, {
		body: t.Object({
			cvss: t.String()
		})
	})
	.listen(3000, ({ hostname, port }) => {
		console.log(
			`Running at ${hostname}:${port}`
		)
	});

export type CVSSApi = typeof app;
