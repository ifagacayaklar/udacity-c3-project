import {Router, Request, Response} from 'express';
import {FeedItem} from '../models/FeedItem';
import {NextFunction} from 'connect';
import * as jwt from 'jsonwebtoken';
import * as AWS from '../../../../aws';
import * as c from '../../../../config/config';
import { v4 as uuid } from 'uuid';
import { AnyARecord } from 'dns';

const router: Router = Router();

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.headers || !req.headers.authorization) {
    return res.status(401).send({message: 'No authorization headers.'});
  }

  const tokenBearer = req.headers.authorization.split(' ');
  if (tokenBearer.length != 2) {
    return res.status(401).send({message: 'Malformed token.'});
  }

  const token = tokenBearer[1];
  return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      return res.status(500).send({auth: false, message: 'Failed to authenticate.'});
    }
    return next();
  });
}

function getUserName (req : Request): string {
  try {
    const tokenBearer = req.headers.authorization.split(' ');
    if (tokenBearer.length != 2){
      throw new Error('Error');
    }
    const token = tokenBearer[1];
    const decoded: any = jwt.verify(token, c.config.jwt.secret);
    return decoded.email
    
  } catch (err){
    return "Anonym";
  }
}

function logFeed (req: Request, username: string, pid: string, before: boolean ) {
  if (before){
    console.log(new Date().toLocaleString() + `: ${pid} - User ${username} requested for ${req.method} -- ${req.originalUrl}`);
  }else {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request by ${username} for ${req.method} -- ${req.originalUrl}`);
  }
}

// Get all feed items
router.get('/', async (req: Request, res: Response) => {
  const pid = uuid();
  const username = await getUserName(req);
  console.log(username)
  await logFeed(req, username, pid, true);
  const items = await FeedItem.findAndCountAll({order: [['id', 'DESC']]});
  items.rows.map((item) => {
    if (item.url) {
      item.url = AWS.getGetSignedUrl(item.url);
    }
  });
  await logFeed(req, username, pid, false);
  res.send(items);
});

// Get a feed resource
router.get('/:id',
    async (req: Request, res: Response) => {
      const pid = uuid();
      const username = getUserName(req);
      logFeed(req, username, pid, true);
      const {id} = req.params;
      const item = await FeedItem.findByPk(id);
      logFeed(req, username, pid, false);
      res.send(item);
    });

// Get a signed url to put a new item in the bucket
router.get('/signed-url/:fileName',
    requireAuth,
    async (req: Request, res: Response) => {
      const pid = uuid();
      const username = getUserName(req);
      logFeed(req, username, pid, true);
      const {fileName} = req.params;
      const url = AWS.getPutSignedUrl(fileName);
      logFeed(req, username, pid, false);
      res.status(201).send({url: url});
    });

// Create feed with metadata
router.post('/',
    requireAuth,
    async (req: Request, res: Response) => {
      const pid = uuid();
      const username = getUserName(req);
      logFeed(req, username, pid, true);
      const caption = req.body.caption;
      const fileName = req.body.url; // same as S3 key name

      if (!caption) {
        logFeed(req, username, pid, false);
        return res.status(400).send({message: 'Caption is required or malformed.'});
      }

      if (!fileName) {
        logFeed(req, username, pid, false);
        return res.status(400).send({message: 'File url is required.'});
      }

      const item = await new FeedItem({
        caption: caption,
        url: fileName,
      });

      const savedItem = await item.save();

      savedItem.url = AWS.getGetSignedUrl(savedItem.url);
      logFeed(req, username, pid, false);
      res.status(201).send(savedItem);
    });

export const FeedRouter: Router = router;
