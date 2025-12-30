# FastAPI JWT Authentication API

This project is a simple JWT-based authentication system built with FastAPI.
It provides basic user registration, login, and protected route access using JSON Web Tokens.

## Features

- User registration
- User login with JWT token generation
- Protected routes with token verification
- Stateless authentication
- API-first design

## Technologies Used

- FastAPI
- Python
- JWT (JSON Web Tokens)
- Pydantic
- Uvicorn

## Endpoints

| Method | Endpoint      | Description              |
|------|--------------|--------------------------|
| POST | /register     | Register a new user      |
| POST | /login        | Login and get JWT token  |
| GET  | /protected    | Protected test endpoint  |

## Getting Started

### Requirements

- Python 3.10+

### Installation

```bash
pip install -r requirements.txt
