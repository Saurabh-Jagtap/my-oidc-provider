import path from 'path'
import { __dirname } from '../utils/paths.js'

export const getLoginPage = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
}

export const getRegisterPage = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'))
}

export const getConsentPage = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'consent.html'))
}

export const getDevDashboard = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dev-dashboard.html'))
}

export const getBecomeDev = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'become-dev.html'))
}

export const getHome = (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'))
}