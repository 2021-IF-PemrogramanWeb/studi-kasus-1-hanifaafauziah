-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Nov 08, 2021 at 01:23 PM
-- Server version: 10.4.21-MariaDB
-- PHP Version: 8.0.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `id17884828_datadummy`
--

-- --------------------------------------------------------

--
-- Table structure for table `employee`
--

CREATE TABLE `employee` (
  `E_ID` int(5) NOT NULL,
  `Nama` varchar(100) NOT NULL,
  `Umur` int(3) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `employee`
--

INSERT INTO `employee` (`E_ID`, `Nama`, `Umur`) VALUES
(1, 'Hani', 24),
(2, 'Sarah', 21),
(3, 'Tuti', 23),
(4, 'Budi', 21),
(5, 'Bambang', 22),
(6, 'Ina', 23),
(7, 'Popo', 21),
(8, 'Farhan', 24);

-- --------------------------------------------------------

--
-- Table structure for table `tables`
--

CREATE TABLE `tables` (
  `no` int(11) NOT NULL,
  `t_on` varchar(50) NOT NULL,
  `t_off` varchar(50) NOT NULL,
  `ack_by` varchar(50) NOT NULL,
  `reason` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `tables`
--

INSERT INTO `tables` (`no`, `t_on`, `t_off`, `ack_by`, `reason`) VALUES
(1, 'Kamis, 25/02/2021, 19:41:50', 'Kamis, 25/02/2021, 21:00:50', 'Act: Audiyatra Dis: Rizaldy, Gathot', '1. Interlock Hose Reel Front'),
(2, 'Minggu, 01/03/2021, 19:41:50', 'Minggu, 01/03/2021, 22:41:50', '', '2. Interlock Hose Reel Rear'),
(3, 'Minggu, 01/03/2021, 23:30:00', 'Minggu, 01/03/2021, 00:30:00', '', '3. Interlock Input Coupler Stow'),
(4, 'Selasa, 03/03/2021, 08:30:30', 'Selasa, 03/03/2021, 09:30:30', '', '4. Interlock Input Hose Boom Stow'),
(5, 'Kamis, 05/03/2021, 08:30:30', 'Kamis, 05/03/2021, 10:30:30', '', '9. Interlock Bonding Static Reel Front'),
(6, 'Jumat, 06/03/2021, 08:30:30', 'Jumat, 06/03/2021, 08:45:30', '', '10. Interlock Bonding Static Reel Rear'),
(7, 'Senin, 08/03/2021, 08:30:30', 'Senin, 08/03/2021, 08:30:30', '', '15. Interlock System Fault'),
(8, 'Selasa, 16/03/2021, 08:30:30', 'Selasa, 16/03/2021, 08:30:30', '', '16. Breakdown');

-- --------------------------------------------------------

--
-- Table structure for table `trend`
--

CREATE TABLE `trend` (
  `id` int(5) NOT NULL,
  `value` int(5) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `trend`
--

INSERT INTO `trend` (`id`, `value`) VALUES
(1, 2),
(2, 3),
(3, 4),
(4, 1),
(5, 2),
(6, 5),
(7, 6),
(8, 7),
(9, 1),
(10, 1),
(11, 1),
(12, 2),
(13, 3),
(14, 2),
(15, 1),
(16, 9);

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(5) NOT NULL,
  `nama` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(200) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `nama`, `email`, `password`) VALUES
(1, 'Hanifa Fauziah', 'hnffzh@gmail.com', '$2y$10$fDbCnXvNjcAw7QMDVusAWOmdvXtS.b1QKtX312Yk1xTdX48tAiO8a'),
(2, 'bibip', 'bibip@gmail.com', '$2y$10$1tyzw7gwJvPcpd95/l/d7.d5wvhk91bGAtP9P3aV0pgxwxOlwwE8C');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `tables`
--
ALTER TABLE `tables`
  ADD PRIMARY KEY (`no`);

--
-- Indexes for table `trend`
--
ALTER TABLE `trend`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `tables`
--
ALTER TABLE `tables`
  MODIFY `no` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `trend`
--
ALTER TABLE `trend`
  MODIFY `id` int(5) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(5) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
