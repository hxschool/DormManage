/*
Navicat MySQL Data Transfer

Source Server         : MySQL
Source Server Version : 50529
Source Host           : 10.88.128.239:3306
Source Database       : db_dorm

Target Server Type    : MYSQL
Target Server Version : 50529
File Encoding         : 65001

Date: 2014-10-08 09:38:16
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `t_admin`
-- ----------------------------
DROP TABLE IF EXISTS `t_admin`;
CREATE TABLE `t_admin` (
  `adminId` int(11) NOT NULL AUTO_INCREMENT,
  `userName` varchar(20) DEFAULT NULL,
  `password` varchar(20) DEFAULT NULL,
  `name` varchar(20) DEFAULT NULL,
  `sex` varchar(10) DEFAULT NULL,
  `tel` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`adminId`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_admin
-- ----------------------------
INSERT INTO `t_admin` VALUES ('1', 'admin', 'admin', 'beyond', '男', '1828888888');

-- ----------------------------
-- Table structure for `t_dorm`
-- ----------------------------
DROP TABLE IF EXISTS `t_dorm`;
CREATE TABLE `t_dorm` (
  `dormId` int(11) NOT NULL AUTO_INCREMENT,
  `dormBuildId` int(11) DEFAULT NULL,
  `dormName` varchar(20) DEFAULT NULL,
  `dormType` varchar(20) DEFAULT NULL,
  `dormNumber` int(11) DEFAULT NULL,
  `dormTel` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`dormId`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_dorm
-- ----------------------------
INSERT INTO `t_dorm` VALUES ('1', '1', '220', '男', '6', '110');

-- ----------------------------
-- Table structure for `t_dormbuild`
-- ----------------------------
DROP TABLE IF EXISTS `t_dormbuild`;
CREATE TABLE `t_dormbuild` (
  `dormBuildId` int(11) NOT NULL AUTO_INCREMENT,
  `dormBuildName` varchar(20) DEFAULT NULL,
  `dormBuildDetail` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`dormBuildId`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_dormbuild
-- ----------------------------
INSERT INTO `t_dormbuild` VALUES ('1', '1栋', '一栋信息介绍');
INSERT INTO `t_dormbuild` VALUES ('4', '2栋', '二栋信息介绍');
INSERT INTO `t_dormbuild` VALUES ('5', '3栋', '三栋信息介绍');
INSERT INTO `t_dormbuild` VALUES ('6', '4栋', '四栋信息介绍');
INSERT INTO `t_dormbuild` VALUES ('7', '5栋', '五栋信息介绍');

-- ----------------------------
-- Table structure for `t_dormmanager`
-- ----------------------------
DROP TABLE IF EXISTS `t_dormmanager`;
CREATE TABLE `t_dormmanager` (
  `dormManId` int(11) NOT NULL AUTO_INCREMENT,
  `userName` varchar(20) DEFAULT NULL,
  `password` varchar(20) DEFAULT NULL,
  `dormBuildId` int(11) DEFAULT NULL,
  `name` varchar(20) DEFAULT NULL,
  `sex` varchar(20) DEFAULT NULL,
  `tel` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`dormManId`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_dormmanager
-- ----------------------------
INSERT INTO `t_dormmanager` VALUES ('2', '测试账号1', '123456', '4', '测试1', '男', '18245697896');
INSERT INTO `t_dormmanager` VALUES ('3', '测试账号', '123', '1', '测试账号', '女', '123');
INSERT INTO `t_dormmanager` VALUES ('4', '测试账号2', '123', '5', '测试2', '男', '123');
INSERT INTO `t_dormmanager` VALUES ('5', '测试账号3', '123', null, '测试3', '男', '18245627896');
INSERT INTO `t_dormmanager` VALUES ('8', '123456', '123456', '6', 'beyond', '男', '18212346589');

-- ----------------------------
-- Table structure for `t_record`
-- ----------------------------
DROP TABLE IF EXISTS `t_record`;
CREATE TABLE `t_record` (
  `recordId` int(11) NOT NULL AUTO_INCREMENT,
  `studentNumber` varchar(20) DEFAULT NULL,
  `studentName` varchar(30) DEFAULT NULL,
  `dormBuildId` int(11) DEFAULT NULL,
  `dormName` varchar(11) DEFAULT NULL,
  `date` date DEFAULT NULL,
  `detail` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`recordId`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_record
-- ----------------------------
INSERT INTO `t_record` VALUES ('1', '002', '李四', '4', '120', '2014-01-01', '123');
INSERT INTO `t_record` VALUES ('3', '007', '测试1', '1', '221', '2014-08-11', '123');

-- ----------------------------
-- Table structure for `t_student`
-- ----------------------------
DROP TABLE IF EXISTS `t_student`;
CREATE TABLE `t_student` (
  `studentId` int(11) NOT NULL AUTO_INCREMENT,
  `stuNum` varchar(20) DEFAULT NULL,
  `password` varchar(20) DEFAULT NULL,
  `name` varchar(20) DEFAULT NULL,
  `dormBuildId` int(11) DEFAULT NULL,
  `dormName` varchar(11) DEFAULT NULL,
  `sex` varchar(10) DEFAULT NULL,
  `tel` varchar(15) DEFAULT NULL,
  PRIMARY KEY (`studentId`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of t_student
-- ----------------------------
INSERT INTO `t_student` VALUES ('2', '002', '123', '李四', '4', '120', '男', '32');
INSERT INTO `t_student` VALUES ('3', '003', '123', '王五', '5', '201', '男', '2');
INSERT INTO `t_student` VALUES ('9', '007', '123', '测试1', '1', '221', '男', '123');
INSERT INTO `t_student` VALUES ('28', '001', '123', '测试1', '1', '111', '男', '123');
INSERT INTO `t_student` VALUES ('29', '008', '123', '测试3', '6', '123', '男', '123');
INSERT INTO `t_student` VALUES ('30', '009', '123', '测试4', '5', '123', '男', '123');
