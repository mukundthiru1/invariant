import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DB_PATH = resolve(__dirname, '../../campaign-db.json');

export interface CampaignRecord {
  email: string;
  template: string;
  sentAt: string;
  opened: boolean;
  openedAt?: string;
  replied: boolean;
  repliedAt?: string;
  converted: boolean;
}

interface DB {
  records: Record<string, CampaignRecord>;
}

function loadDB(): DB {
  try {
    const data = readFileSync(DB_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return { records: {} };
  }
}

function saveDB(db: DB) {
  writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
}

export function recordSend(email: string, template: string) {
  const db = loadDB();
  db.records[email] = {
    email,
    template,
    sentAt: new Date().toISOString(),
    opened: false,
    replied: false,
    converted: false,
  };
  saveDB(db);
}

export function recordOpen(email: string) {
  const db = loadDB();
  if (db.records[email] && !db.records[email].opened) {
    db.records[email].opened = true;
    db.records[email].openedAt = new Date().toISOString();
    saveDB(db);
  }
}

export function recordReply(email: string, converted: boolean = false) {
  const db = loadDB();
  if (db.records[email]) {
    db.records[email].replied = true;
    db.records[email].repliedAt = new Date().toISOString();
    if (converted) {
      db.records[email].converted = true;
    }
    saveDB(db);
  }
}

export function getCampaignStats() {
  const db = loadDB();
  const records = Object.values(db.records);
  const totalSent = records.length;
  const totalOpened = records.filter(r => r.opened).length;
  const totalReplied = records.filter(r => r.replied).length;
  const totalConverted = records.filter(r => r.converted).length;

  const templateStats: Record<string, { sent: number, opened: number, replied: number, converted: number }> = {};
  for (const r of records) {
    if (!templateStats[r.template]) {
      templateStats[r.template] = { sent: 0, opened: 0, replied: 0, converted: 0 };
    }
    templateStats[r.template].sent++;
    if (r.opened) templateStats[r.template].opened++;
    if (r.replied) templateStats[r.template].replied++;
    if (r.converted) templateStats[r.template].converted++;
  }

  return {
    totalSent,
    totalOpened,
    totalReplied,
    totalConverted,
    templateStats,
  };
}
