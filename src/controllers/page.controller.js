import path from 'path'
import { __dirname } from '../utils/paths.js'

export const getLoginPage = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
}

export const getRegisterPage = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'))
}
