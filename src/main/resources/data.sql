INSERT INTO customers (name, contact_name, email, phone) values ('Acme', 'Wylie Coyote', 'wcoyote@acme.com', '1-515-555-2348');
INSERT INTO customers (name, contact_name, email, phone) values ('Spacely Space Sprockets', 'George Jettson', 'gjettson@spacely.com', '1-515-555-2350');
INSERT INTO customers (name, contact_name, email, phone) values ('Callahan Auto', 'Thomas Callhan', 'tcallahan@callhhanauto.com', '1-515-555-2333');
INSERT INTO customers (name, contact_name, email, phone) values ('Dundler Mifflin Inc', 'Michael Scott', 'mscott@dundlermifflin.com', '1-515-555-2320');
INSERT INTO customers (name, contact_name, email, phone) values ('Stark Industries', 'Tony Stark', 'tstark@stark.com', '1-515-555-7777');
INSERT INTO customers (name, contact_name, email, phone) values ('Initech', 'Peter Gibbons', 'pgibbons@initec.com', '1-515-555-0666');
INSERT INTO customers (name, contact_name, email, phone) values ('Wayne Enterprises', 'Bruce Wayne', 'bwayne@wayne.com', '1-515-555-1111');

INSERT INTO orders (customer_id, order_info) values ((SELECT customer_id FROM customers where name = 'Acme'), '1500 Widgets');
INSERT INTO orders (customer_id, order_info) values ((SELECT customer_id FROM customers where name = 'Acme'), '3000 Widgets');
INSERT INTO orders (customer_id, order_info) values ((SELECT customer_id FROM customers where name = 'Callahan Auto'), '200 Widgets');

INSERT INTO users_old (username, password, enabled) values('user', '{bcrypt}$2a$10$2VuuG7NKl7FLJyk0cp/OK.0VlBAfnz8uijD3beCjRvaVVdfpHxC3i', true);
INSERT INTO users_old (username, password, enabled) values('admin', '{bcrypt}$2a$10$2VuuG7NKl7FLJyk0cp/OK.0VlBAfnz8uijD3beCjRvaVVdfpHxC3i', true);

INSERT INTO authorities_old(username, authority) values ('user', 'ROLE_USER');
INSERT INTO authorities_old(username, authority) values ('admin', 'ROLE_ADMIN');
INSERT INTO authorities_old(username, authority) values ('admin', 'ROLE_USER');