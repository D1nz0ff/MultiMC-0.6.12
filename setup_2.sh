#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display a message and exit
function error_exit {
  echo "$1" 1>&2
  exit 1
}

# Install dependencies
echo "Installing dependencies..."
sudo apt update
sudo apt install -y postgresql postgresql-contrib nodejs npm || error_exit "Failed to install dependencies."

# Setup PostgreSQL database and user
DB_NAME="forum_db"
DB_USER="forum_user"
DB_PASSWORD="forum_password"
DB_HOST="localhost"
DB_PORT="5432"

echo "Creating PostgreSQL database and user..."
sudo -u postgres psql <<EOF
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS $DB_USER;
CREATE DATABASE $DB_NAME;
CREATE USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

# Backend setup
echo "Setting up backend..."
mkdir -p forum/backend
cd forum/backend

# Initialize npm and install backend dependencies
npm init -y
npm install express typeorm reflect-metadata pg bcrypt jsonwebtoken dotenv cors helmet
npm install @types/express @types/bcrypt @types/jsonwebtoken @types/cors ts-node typescript @types/node --save-dev

# Create TypeScript configuration file
cat > tsconfig.json <<EOL
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "./dist",
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["./**/*.ts"],
  "exclude": ["node_modules"]
}
EOL

# Create .env file for environment variables
cat > .env <<EOL
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_USERNAME=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_DATABASE=$DB_NAME
JWT_SECRET="your-secret-key"
PORT=3000
EOL

# Create app.ts file
cat > src/app.ts <<EOL
import 'reflect-metadata';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { createConnection } from 'typeorm';
import authRoutes from './routes/authRoutes';
import topicRoutes from './routes/topicRoutes';
import postRoutes from './routes/postRoutes';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(helmet());
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/topics', topicRoutes);
app.use('/posts', postRoutes);

createConnection().then(() => {
  app.listen(port, () => {
    console.log(\`Server is running on port \${port}\`);
  });
}).catch(error => console.log(error));

export default app;
EOL

# Create entities
mkdir -p src/entities
cat > src/entities/User.ts <<EOL
import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Post } from './Post';
import { Topic } from './Topic';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  username: string;

  @Column()
  password: string;

  @OneToMany(() => Post, post => post.user)
  posts: Post[];

  @OneToMany(() => Topic, topic => topic.user)
  topics: Topic[];
}
EOL

cat > src/entities/Topic.ts <<EOL
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany } from 'typeorm';
import { User } from './User';
import { Post } from './Post';

@Entity()
export class Topic {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  title: string;

  @Column()
  content: string;

  @ManyToOne(() => User, user => user.topics)
  user: User;

  @OneToMany(() => Post, post => post.topic)
  posts: Post[];
}
EOL

cat > src/entities/Post.ts <<EOL
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { User } from './User';
import { Topic } from './Topic';

@Entity()
export class Post {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  content: string;

  @ManyToOne(() => User, user => user.posts)
  user: User;

  @ManyToOne(() => Topic, topic => topic.posts)
  topic: Topic;
}
EOL

# Create controllers
mkdir -p src/controllers
cat > src/controllers/authController.ts <<EOL
import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { getRepository } from 'typeorm';
import { User } from '../entities/User';

export const register = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const userRepository = getRepository(User);
  
  const userExists = await userRepository.findOne({ where: { username } });
  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = userRepository.create({ username, password: hashedPassword });
  await userRepository.save(user);

  return res.status(201).json({ message: 'User created' });
};

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const userRepository = getRepository(User);

  const user = await userRepository.findOne({ where: { username } });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' });

  return res.status(200).json({ token });
};
EOL

cat > src/controllers/topicController.ts <<EOL
import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import { Topic } from '../entities/Topic';
import { User } from '../entities/User';

export const createTopic = async (req: Request, res: Response) => {
  const { title, content } = req.body;
  const userId = (req as any).userId;

  const topicRepository = getRepository(Topic);
  const userRepository = getRepository(User);

  const user = await userRepository.findOne(userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const topic = topicRepository.create({ title, content, user });
  await topicRepository.save(topic);

  return res.status(201).json(topic);
};

export const getTopics = async (req: Request, res: Response) => {
  const topicRepository = getRepository(Topic);
  const topics = await topicRepository.find({ relations: ['user'] });
  return res.json(topics);
};

export const getTopic = async (req: Request, res: Response) => {
  const { id } = req.params;
  const topicRepository = getRepository(Topic);
  const topic = await topicRepository.findOne(id, { relations: ['user', 'posts', 'posts.user'] });
  
  if (!topic) {
    return res.status(404).json({ message: 'Topic not found' });
  }

  return res.json(topic);
};
EOL

cat > src/controllers/postController.ts <<EOL
import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import { Post } from '../entities/Post';
import { User } from '../entities/User';
import { Topic } from '../entities/Topic';

export const createPost = async (req: Request, res: Response) => {
  const { content, topicId } = req.body;
  const userId = (req as any).userId;

  const postRepository = getRepository(Post);
  const userRepository = getRepository(User);
  const topicRepository = getRepository(Topic);

  const user = await userRepository.findOne(userId);
  const topic = await topicRepository.findOne(topicId);

  if (!user || !topic) {
    return res.status(404).json({ message: 'User or Topic not found' });
  }

  const post = postRepository.create({ content, user, topic });
  await postRepository.save(post);

  return res.status(201).json(post);
};

export const getPosts = async (req: Request, res: Response) => {
  const { topicId } = req.params;
  const postRepository = getRepository(Post);
  const posts = await postRepository.find({ 
    where: { topic: { id: topicId } },
    relations: ['user']
  });
  return res.json(posts);
};
EOL

# Create routes
mkdir -p src/routes
cat > src/routes/authRoutes.ts <<EOL
import { Router } from 'express';
import { register, login } from '../controllers/authController';

const router = Router();

router.post('/register', register);
router.post('/login', login);

export default router;
EOL

cat > src/routes/topicRoutes.ts <<EOL
import { Router } from 'express';
import { createTopic, getTopics, getTopic } from '../controllers/topicController';
import { authMiddleware } from '../middleware/authMiddleware';

const router = Router();

router.post('/', authMiddleware, createTopic);
router.get('/', getTopics);
router.get('/:id', getTopic);

export default router;
EOL

cat > src/routes/postRoutes.ts <<EOL
import { Router } from 'express';
import { createPost, getPosts } from '../controllers/postController';
import { authMiddleware } from '../middleware/authMiddleware';

const router = Router();

router.post('/', authMiddleware, createPost);
router.get('/:topicId', getPosts);

export default router;
EOL

# Create middleware
mkdir -p src/middleware
cat > src/middleware/authMiddleware.ts <<EOL
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { id: number };
    (req as any).userId = decoded.id;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};
EOL

# Frontend setup
echo "Setting up frontend..."
cd ../../
npx create-react-app frontend --template typescript
cd frontend

# Install frontend dependencies
npm install axios react-router-dom @types/react-router-dom @material-ui/core @material-ui/icons

# Create API setup
mkdir -p src/api
cat > src/api/axios.ts <<EOL
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:3000',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = \`Bearer \${token}\`;
  }
  return config;
});

export default api;
EOL

# Create context
mkdir -p src/context
cat > src/context/AuthContext.tsx <<EOL
import React, { createContext, useState, useContext, ReactNode } from 'react';

interface AuthContextType {
  token: string | null;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));

  const login = (token: string) => {
    localStorage.setItem('token', token);
    setToken(token);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
EOL

# Create components
mkdir -p src/components
cat > src/components/Header.tsx <<EOL
import React from 'react';
import { AppBar, Toolbar, Typography, Button } from '@material-ui/core';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Header: React.FC = () => {
  const { token, logout } = useAuth();

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" style={{ flexGrow: 1 }}>
          <Link to="/" style={{ color: 'white', textDecoration: 'none' }}>Forum</Link>
        </Typography>
        {token ? (
          <Button color="inherit" onClick={logout}>Logout</Button>
        ) : (
          <>
            <Button color="inherit" component={Link} to="/login">Login</Button>
            <Button color="inherit" component={Link} to="/register">Register</Button>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Header;
EOL

# Create pages
mkdir -p src/pages
cat > src/pages/LoginPage.tsx <<EOL
import React, { useState } from 'react';
import { TextField, Button, Container, Typography } from '@material-ui/core';
import { useHistory } from 'react-router-dom';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const history = useHistory();
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.post('/auth/login', { username, password });
      login(response.data.token);
      history.push('/');
    } catch (error) {
      console.error('Login failed', error);
    }
  };

  return (
    <Container maxWidth="xs">
      <Typography variant="h4" style={{ marginTop: '2rem', marginBottom: '1rem' }}>Login</Typography>
      <form onSubmit={handleSubmit}>
        <TextField
          variant="outlined"
          margin="normal"
          required
          fullWidth
          label="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextField
          variant="outlined"
          margin="normal"
          required
          fullWidth
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button
          type="submit"
          fullWidth
          variant="contained"
          color="primary"
          style={{ marginTop: '1rem' }}
        >
          Login
        </Button>
      </form>
    </Container>
  );
};

export default LoginPage;
EOL

cat > src/pages/RegisterPage.tsx <<EOL
import React, { useState } from 'react';
import { TextField, Button, Container, Typography } from '@material-ui/core';
import { useHistory } from 'react-router-dom';
import api from '../api/axios';

const RegisterPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const history = useHistory();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/auth/register', { username, password });
      history.push('/login');
    } catch (error) {
      console.error('Registration failed', error);
    }
  };

  return (
    <Container maxWidth="xs">
      <Typography variant="h4" style={{ marginTop: '2rem', marginBottom: '1rem' }}>Register</Typography>
      <form onSubmit={handleSubmit}>
        <TextField
          variant="outlined"
          margin="normal"
          required
          fullWidth
          label="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextField
          variant="outlined"
          margin="normal"
          required
          fullWidth
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button
          type="submit"
          fullWidth
          variant="contained"
          color="primary"
          style={{ marginTop: '1rem' }}
        >
          Register
        </Button>
      </form>
    </Container>
  );
};

export default RegisterPage;
EOL

cat > src/pages/TopicListPage.tsx <<EOL
import React, { useState, useEffect } from 'react';
import { Container, Typography, List, ListItem, ListItemText, Button } from '@material-ui/core';
import { Link } from 'react-router-dom';
import api from '../api/axios';

interface Topic {
  id: number;
  title: string;
  user: {
    username: string;
  };
}

const TopicListPage: React.FC = () => {
  const [topics, setTopics] = useState<Topic[]>([]);

  useEffect(() => {
    const fetchTopics = async () => {
      try {
        const response = await api.get('/topics');
        setTopics(response.data);
      } catch (error) {
        console.error('Failed to fetch topics', error);
      }
    };
    fetchTopics();
  }, []);

  return (
    <Container>
      <Typography variant="h4" style={{ marginTop: '2rem', marginBottom: '1rem' }}>Topics</Typography>
      <Button component={Link} to="/create-topic" variant="contained" color="primary" style={{ marginBottom: '1rem' }}>
        Create New Topic
      </Button>
      <List>
        {topics.map((topic) => (
          <ListItem key={topic.id} button component={Link} to={`/topics/${topic.id}`}>
            <ListItemText 
              primary={topic.title}
              secondary={`Created by ${topic.user.username}`}
            />
          </ListItem>
        ))}
      </List>
    </Container>
  );
};

export default TopicListPage;
EOL

cat > src/pages/TopicPage.tsx <<EOL
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Container, Typography, TextField, Button, List, ListItem, ListItemText } from '@material-ui/core';
import api from '../api/axios';

interface Post {
  id: number;
  content: string;
  user: {
    username: string;
  };
}

interface Topic {
  id: number;
  title: string;
  content: string;
  user: {
    username: string;
  };
  posts: Post[];
}

const TopicPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [topic, setTopic] = useState<Topic | null>(null);
  const [newPost, setNewPost] = useState('');

  useEffect(() => {
    const fetchTopic = async () => {
      try {
        const response = await api.get(`/topics/${id}`);
        setTopic(response.data);
      } catch (error) {
        console.error('Failed to fetch topic', error);
      }
    };
    fetchTopic();
  }, [id]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.post('/posts', { content: newPost, topicId: id });
      setTopic(prev => prev ? { ...prev, posts: [...prev.posts, response.data] } : null);
      setNewPost('');
    } catch (error) {
      console.error('Failed to create post', error);
    }
  };

  if (!topic) return <div>Loading...</div>;

  return (
    <Container>
      <Typography variant="h4" style={{ marginTop: '2rem', marginBottom: '1rem' }}>{topic.title}</Typography>
      <Typography variant="body1">{topic.content}</Typography>
      <Typography variant="caption">Posted by {topic.user.username}</Typography>
      
      <Typography variant="h5" style={{ marginTop: '2rem', marginBottom: '1rem' }}>Posts</Typography>
      <List>
        {topic.posts.map((post) => (
          <ListItem key={post.id}>
            <ListItemText 
              primary={post.content}
              secondary={`Posted by ${post.user.username}`}
            />
          </ListItem>
        ))}
      </List>

      <Typography variant="h6" style={{ marginTop: '2rem', marginBottom: '1rem' }}>Add a Post</Typography>
      <form onSubmit={handleSubmit}>
        <TextField
          variant="outlined"
          margin="normal"
          required
          fullWidth
          label="Your post"
          value={newPost}
          onChange={(e) => setNewPost(e.target.value)}
          multiline
          rows={4}
        />
        <Button
          type="submit"
          variant="contained"
          color="primary"
          style={{ marginTop: '1rem' }}
        >
          Submit Post
        </Button>
      </form>
    </Container>
  );
};

export default TopicPage;
EOL

# Update App.tsx
cat > src/App.tsx <<EOL
import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Header from './components/Header';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import TopicListPage from './pages/TopicListPage';
import TopicPage from './pages/TopicPage';

const App: React.FC = () => {
  return (
    <AuthProvider>
      <Router>
        <Header />
        <Switch>
          <Route exact path="/" component={TopicListPage} />
          <Route path="/login" component={LoginPage} />
          <Route path="/register" component={RegisterPage} />
          <Route path="/topics/:id" component={TopicPage} />
        </Switch>
      </Router>
    </AuthProvider>
  );
};

export default App;
EOL

# Update index.tsx
cat > src/index.tsx <<EOL
import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import { ThemeProvider, createTheme } from '@material-ui/core/styles';

const theme = createTheme();

ReactDOM.render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <App />
    </ThemeProvider>
  </React.StrictMode>,
  document.getElementById('root')
);
EOL

# Final setup steps
cd ..
echo "Setting up final configurations..."

# Update backend package.json
cd backend
npm pkg set scripts.start="ts-node src/app.ts"
npm pkg set scripts.build="tsc"
cd ..

# Update frontend package.json
cd frontend
npm pkg set scripts.start="react-scripts start"
npm pkg set scripts.build="react-scripts build"
cd ..

echo "Setup complete! To start the application:"
echo "1. In one terminal, navigate to the backend folder and run: npm start"
echo "2. In another terminal, navigate to the frontend folder and run: npm start"
echo "3. Open your browser and go to http://localhost:3000"

# End of script