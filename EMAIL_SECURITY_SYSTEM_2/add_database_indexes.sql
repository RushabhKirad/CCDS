-- Database Performance Optimization
-- Add indexes to frequently queried columns

-- Index on user_email for faster user-specific queries
CREATE INDEX IF NOT EXISTS idx_user_email ON emails(user_email);

-- Index on label for faster filtering by classification
CREATE INDEX IF NOT EXISTS idx_label ON emails(label);

-- Index on created_at for faster sorting by date
CREATE INDEX IF NOT EXISTS idx_created_at ON emails(created_at);

-- Index on sender for faster sender-based queries
CREATE INDEX IF NOT EXISTS idx_sender ON emails(sender);

-- Index on is_read for faster unread email queries
CREATE INDEX IF NOT EXISTS idx_is_read ON emails(is_read);

-- Index on is_starred for faster starred email queries
CREATE INDEX IF NOT EXISTS idx_is_starred ON emails(is_starred);

-- Composite index for common query patterns
CREATE INDEX IF NOT EXISTS idx_user_label ON emails(user_email, label);

-- Show indexes
SHOW INDEX FROM emails;
