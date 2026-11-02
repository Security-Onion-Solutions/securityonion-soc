-- Migration: ADD recipients column to notifications table

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS recipients JSONB DEFAULT '[]'::jsonb;
