#!/bin/bash
#SBATCH -J openfhe-build
#SBATCH -o openfhe-build.o%j
#SBATCH -e openfhe-build.e%j
#SBATCH -p gh-dev
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 01:00:00
#SBATCH -A MCB25091
export GCC_MODULE=gcc/15.1.0

module load cmake
bash build_openfhe_ls6.sh
