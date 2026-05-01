export const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:4000',
    'http://127.0.0.1:3001',
    'http://192.168.0.197:3001',
    ...(process.env.CORS_ORIGINS?.split(',').map(origin => origin.trim()).filter(Boolean) ?? [])
]


export const corsOptions = {
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true)
        }

        return callback(new Error(`Origin ${origin} is not allowed by CORS`))
    },
    credentials: true
}
