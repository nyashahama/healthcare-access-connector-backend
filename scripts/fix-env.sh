#!/bin/bash

# Fix Environment Setup Script
# This script fixes your .env setup to use symlinks

set -e

echo "=================================="
echo "Fixing Environment Setup"
echo "=================================="
echo ""

# Check if .env.development exists
if [ ! -f .env.development ]; then
    echo "❌ Error: .env.development not found"
    echo "Please create .env.development first"
    exit 1
fi

# Check if .env.production exists
if [ ! -f .env.production ]; then
    echo "❌ Error: .env.production not found"
    echo "Please create .env.production first"
    exit 1
fi

echo "✓ Found .env.development"
echo "✓ Found .env.production"
echo ""

# Handle existing .env file
if [ -e .env ]; then
    if [ -L .env ]; then
        target=$(readlink .env)
        echo "ℹ️  .env is already a symlink pointing to: $target"
        echo ""
        read -p "Do you want to recreate it? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Keeping existing symlink"
            exit 0
        fi
        rm .env
    else
        echo "⚠️  .env exists as a regular file"
        echo ""
        read -p "Backup and replace with symlink? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            mv .env .env.backup
            echo "✓ Backed up to .env.backup"
        else
            echo "Cancelled. Please handle .env manually"
            exit 1
        fi
    fi
fi

# Create symlink to development
echo "Creating symlink: .env → .env.development"
ln -s .env.development .env

# Verify
if [ -L .env ]; then
    target=$(readlink .env)
    echo ""
    echo "=================================="
    echo "✓ Setup Complete!"
    echo "=================================="
    echo ""
    echo ".env is now a symlink pointing to: $target"
    echo ""
    echo "You can now use:"
    echo "  make dev          - Development mode"
    echo "  make prod         - Production mode"
    echo "  make env-status   - Check current environment"
    echo "  make switch-dev   - Switch to development"
    echo "  make switch-prod  - Switch to production"
    echo ""
else
    echo ""
    echo "❌ Failed to create symlink"
    exit 1
fi