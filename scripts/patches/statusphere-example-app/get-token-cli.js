import { fileURLToPath } from 'node:url'

import util from 'node:util'
import path from 'node:path'
import { Agent } from '@atproto/api'
import { createDb } from './dist/db.js'
import { SessionStore } from './dist/auth/storage.js'
import { createClient } from './dist/auth/client.js'

const PDS_URL = 'https://bsky.social'

async function main() {
  const args = process.argv.slice(2)
  if (args.length !== 1) {
    console.error('Usage: node get-token-cli.js <user_did>')
    console.error('Example: node get-token-cli.js did:plc:z72i7hdynmk6r22z27h6tvur')
    process.exit(1)
  }

  const userDid = args[0]

  try {
    // 1. Initialize and read the database, same as the app.
    const db = createDb(process.env.DB_PATH)

    // const sessionStore = new SessionStore(db)
    const oauthClient = await createClient(db)

    // 2. Retrieve the raw session data from the database.
    const oauthSession = await oauthClient.restore(userDid)

    if (!oauthSession) {
      console.error(`❌ Error: No saved session found for DID: ${userDid}`)
      console.error(`Please make sure the user has logged in to the Statusphere app at least once.`)
      process.exit(1)
    }

    // 3. Use AtpAgent to resume the session. This will handle token refreshes.
    const agent = new Agent(oauthSession)
    // await agent.post({text: "test"})
    const profile = await agent.getProfile({ actor: userDid })

    console.error("oauthSession.server.dpopKey =", oauthSession.server.dpopKey)

    // 4. Try multiple ways to find the access token.
    const token_set = await oauthSession.getTokenSet('auto');

    if (!token_set.access_token) {
      console.error(`❌ Error: Could not retrieve access token from the session for DID: ${userDid}`)
      process.exit(1)
    }

    token_set.jwk = oauthSession.server.dpopKey.jwk

    console.error(`✅ Access Token for ${userDid}`)
    console.log(JSON.stringify(token_set))
    // console.log(token_set.token_type, token_set.access_token)

  } catch (error) {
   console.error(`\n❌ An unexpected error occurred:`)
    console.error(error)
    process.exit(1)
  }
}

main()
