#!/bin/bash
#SBATCH -J openfhe-build
#SBATCH -o openfhe-build.o%j
#SBATCH -e openfhe-build.e%j
#SBATCH -p development
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 01:00:00
#SBATCH -A MCB25091

module load gcc/15.2.0
module load cmake
bash build_openfhe_ls6.sh
