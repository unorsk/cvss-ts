import { Elysia } from 'elysia'
import { staticPlugin } from '@elysiajs/static'

const app = new Elysia()
	.use(staticPlugin({
    assets: 'dist', // Serve files from the dist folder
    prefix: '/', // Serve files at the root path
  }))
	.listen(3001, ({ hostname, port }) => {
		console.log(
			`🦊 Elysia is running at ${hostname}:${port}`
		)
	})
