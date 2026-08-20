FROM node:22-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY app ./app
COPY next.config.mjs .
RUN npm run build
CMD ["npm","start"]
