#!/bin/sh
sudo umount test
sudo rmmod simplefs
rm -rf test
rm test.img
