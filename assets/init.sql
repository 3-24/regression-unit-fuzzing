CREATE DATABASE IF NOT EXISTS RegressionUnit;
USE RegressionUnit;

CREATE TABLE IF NOT EXISTS function (
    project VARCHAR(255) NOT NULL,
    function_name VARCHAR(255) NOT NULL,
    declaration TEXT NOT NULL,
    UNIQUE(project, function_name)
);

CREATE TABLE IF NOT EXISTS system_carving (
    project VARCHAR(255) NOT NULL,
    function_name VARCHAR(255) NOT NULL,
    context TEXT NOT NULL,
    context_hash bigint not null,
    UNIQUE (project, function_name, context_hash)
);

CREATE TABLE IF NOT EXISTS unit_carving (
    project VARCHAR(255) NOT NULL,
    function_name VARCHAR(255) NOT NULL,
    testcase VARCHAR(255) NOT NULL,
    context TEXT NOT NULL,
    context_hash bigint not null,
    is_crash BOOLEAN NOT NULL,
    sanitizer_report TEXT,
    expr_index INT NOT NULL,
    UNIQUE(project, function_name, context_hash, expr_index)
);

CREATE TABLE IF NOT EXISTS system_fuzz(
    project VARCHAR(255) NOT NULL,
    testcase VARCHAR(255) NOT NULL,
    sanitizer_report TEXT,
    expr_index INT NOT NULL,
    UNIQUE(project, testcase, expr_index)
)