import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'


export const router = new Router()
const prisma = new PrismaClient()


router.get('/tweets', async ctx => {
  const [, token] = ctx.request.headers?.authorization?.split(' ') || []
  try {
    jwt.verify(token, process.env.JWT_SECRET) // verifica o token do usuário
    const tweets = await prisma.tweet.findMany({
      include: {          // esse include é feito para ele relacionar a tabela user com a tabela tweet
        user: true,
      },
    })
    ctx.body = tweets

  } catch (error) {
    ctx.status = 401
    return
  }

})

router.post('/tweets', async ctx => {
  const [, token] = ctx.request.headers?.authorization?.split(' ') || []

  if (!token) {
    ctx.status = 401
    return
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET) // verifica o token do usuário
    const tweet = await prisma.tweet.create({
      data: {
        userId: payload.sub,
        text: ctx.request.body.text
      }
    })

    ctx.body = tweet
  
  } catch (error) {
    if(typeof error === 'JsonWebTokenError') {
    ctx.status = 401
    return
    }

    ctx.status = 500
  }

})

router.post('/signup', async ctx => { //criar o user
  const saltRounds = 10;
  const password = bcrypt.hashSync(ctx.request.body.password, saltRounds);

  try {
    const user = await prisma.user.create({
      data: {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password
      }
    })
  
    const accessToken = jwt.sign({
      sub: user.id,
    }, process.env.JWT_SECRET, { expiresIn: '24h' })

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken
    } //retorna o user sem a senha
  } catch (error) {
    if (error.meta && !error.meta.target) {
      ctx.status = 422
      ctx.body = "Email ou nome de usuário já existe."
      return
    }
    ctx.status = 500
    ctx.body = "Internal Error"
  }
})


router.get('/login', async ctx => {
  const [, token] = ctx.request.headers.authorization.split(' ')
  const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':')

  const saltRounds = 10

  const user = await prisma.user.findUnique({
    where: { email }
  })

  if (!user) {
    ctx.status = 404
    return
  }

  const passwordMatch = bcrypt.compareSync(plainTextPassword, user.password)

  if (passwordMatch) {
    const accessToken = jwt.sign({
      sub: user.id,
    }, process.env.JWT_SECRET, { expiresIn: '24h' })

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken
    }

    return
  }

  ctx.status = 404
})