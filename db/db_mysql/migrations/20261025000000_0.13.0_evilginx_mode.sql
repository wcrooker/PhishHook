
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE campaigns ADD COLUMN encryption_key varchar(255);
ALTER TABLE campaigns ADD COLUMN evilginx_mode boolean NOT NULL DEFAULT '0';
ALTER TABLE email_requests ADD COLUMN encryption_key varchar(255);
ALTER TABLE email_requests ADD COLUMN evilginx_mode boolean NOT NULL DEFAULT '0';

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
