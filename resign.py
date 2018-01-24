#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zipfile
import os.path
import os
import time
import shutil
import subprocess
import plistlib

signextensions      = ['.framework/','.dylib','.appex/','.app/']
bundleidentifierkey = 'CFBundleIdentifier'
replaceplistkey     = 'BundleIdentifier'
oldbundleId         = None 
uncheckedfiles      = [] #暂未检查bundleId文件列表
certificatelist     = [] #证书列表

#拷贝mobileprovsion到xxx.app目录
def copyprovsion2appdir(originpath,mobileprovision):
	for dirpath, dirnames, filenames in os.walk(originpath):
		if dirpath[dirpath.rfind('.'):] == '.app':
			shutil.copy(mobileprovision,'%s/%s' % (dirpath,'embedded.mobileprovision'))
			return True
	return False

#根据mobileprovision生成entitlements.plist文件
def generateentitlements(mobileprovisionpath,entilementspath):
	entilementfull = entilementspath[:entilementspath.rfind('.')] + '_full.plist'
	(status1, output1) = subprocess.getstatusoutput('security cms -D -i "%s" > %s' % (mobileprovisionpath, entilementfull))
	(status2, output2) = subprocess.getstatusoutput('/usr/libexec/PlistBuddy -x -c "Print:Entitlements" %s > %s' % (entilementfull,entilementspath))
	return status1 == 0 and status2 == 0


#修改BundleIdentifier
def modifyBundleIdentifer(originpath,newBundleIdentifier):
	for dirpath,dirnames, filenames in os.walk(originpath):
		for filename in filenames:
			if os.path.split(filename)[-1] == 'Info.plist':
				modifyPlistBundleId(os.path.join(dirpath, filename),newBundleIdentifier)
	for filepath in uncheckedfiles:
		modifyPlistBundleId(filepath,newBundleIdentifier)

#修改Plist文件
def modifyPlistBundleId(filepath,newBundleIdentifier):
	with open(filepath, 'rb') as fp:
		pl = plistlib.load(fp)
		global oldbundleId
		if oldbundleId == None:
			oldbundleId = pl.get(bundleidentifierkey)
		if oldbundleId == None:
			uncheckedfiles.append(filepath)
			return
		for key in pl.keys():
			if replaceplistkey in key:
				pl[key] = pl[key].replace(oldbundleId,newBundleIdentifier)
			elif key == 'NSExtension' and 'NSExtensionAttributes' in pl['NSExtension'] and 'WKAppBundleIdentifier' in pl['NSExtension']['NSExtensionAttributes']:
				extAtts = pl['NSExtension']['NSExtensionAttributes']
				extAtts['WKAppBundleIdentifier'] = extAtts['WKAppBundleIdentifier'].replace(oldbundleId,newBundleIdentifier)
		with open(filepath, 'wb') as fp:
			plistlib.dump(pl, fp)

#获取证书列表
def getCertificates():
	try:
		(status,output) = subprocess.getstatusoutput('security find-identity -v -p codesigning')
		print(' 序号\t\t\tSHA-1\t\t\t证书名称')
		global certificatelist
		certificatelist = output.split('\n')
		certificatelist.pop(-1)
		print('\n'.join(certificatelist))
		return True
	except Exception as e:
		print(e)
		return False

#文件是否需要签名
def isneedsign(filename):
	for signextension in signextensions:
		if signextension == filename[filename.rfind('.'):]:
			return True
	return False

#签名
def codesign(certificate,entilement,signObj,extrapath):
	(status, output) = subprocess.getstatusoutput('codesign -f -s "%s" --entitlements "%s" "%s"' % (certificate,entilement,'%s/%s' % (extrapath,signObj)))
	if status == 0 and 'replacing existing signature' in output:
		print('replacing %s existing signature successed' % signObj)
		return True
	else:
		print(output)
		return False

#开始签名
def startsign(certificate,entilement,zfilelist,extrapath):
	print("----------------开始签名----------------")
	for filename in zfilelist:
		if isneedsign(filename):
			if not codesign(certificate,entilement,filename,extrapath):
	 			return False
	return True

#zip压缩
def zipcompress(originpath,destinationzfile):
	resignedzfile = zipfile.ZipFile(destinationzfile,'w',zipfile.ZIP_DEFLATED)
	for dirpath, dirnames, filenames in os.walk(originpath):
		fpath = dirpath.replace(originpath,'')
		fpath = fpath and fpath + os.sep or ''
		for filename in filenames:
			resignedzfile.write(os.path.join(dirpath, filename), fpath+filename)
	resignedzfile.close()

#验证签名
def verifySignature(extralfilepath):
	for dirpath, dirnames, filenames in os.walk(extralfilepath):
		if dirpath[dirpath.rfind('.'):] == '.app':
			(status,output) = subprocess.getstatusoutput('codesign -v %s' % dirpath)
			if len(output) == 0:
				return True
			else:
				print(output)
				return False
	return False

def main():
	zipFilePath = input('请拖拽ipa到此：').strip()

	homedir = os.environ['HOME']
	extrapath = '%s/Payload_temp_%s/' % (homedir,str(time.time()))

	#获取证书列表
	if not getCertificates():
		return False

	try:
		certificateindexstr = input('请输入签名证书序号：').strip()
		certificateindex = int(certificateindexstr)
		if certificateindex < 1 or certificateindex > len(certificatelist):
			print('签名证书选择有误,请重试')
			return False
		else:
			selcert = certificatelist[certificateindex-1]
			certificate = selcert[selcert.find('"')+1:selcert.rfind('"')]
			print("你选择的签名证书是："+certificate)
	except Exception as e:
		print('签名证书选择有误,请重试')
		return False

	mobileprovision = input('请拖拽mobileprovsion到此：').strip()
	newBundleIdentifier = input('请输入新的BundleId(请与mobileprovision匹配，不输入则不修改BundleId)：').strip()
	entilement  = extrapath + "entitlements.plist"

	destinationzfile = zipFilePath[:zipFilePath.rfind('.')] + '_resigned.ipa'

	originzfile = zipfile.ZipFile(zipFilePath,'r')
	zfilelist = originzfile.namelist()
	zfilelist.reverse()

	#解压到临时目录
	originzfile.extractall(extrapath)

	#修改BundleIdentifier
	if newBundleIdentifier != '':
		modifyBundleIdentifer(extrapath,newBundleIdentifier)

	#拷贝mobileprovsion
	copyprovsion2appdir(extrapath, mobileprovision)

	#生成entitlement.plist文件
	if not generateentitlements(mobileprovision,entilement):
		print("生成entitlements.plist文件失败!")
		#关闭zipfile
		originzfile.close()
		#删除临时解压目录
		shutil.rmtree(extrapath)
		return False
		
	try:
		#开始签名
		if zfilelist != None and startsign(certificate,entilement,zfilelist,extrapath):
			print("-------------签名完成，开始验证签名-------------")
			if verifySignature(extrapath):
				print("-------------验签成功，开始打包-------------")
				zipcompress(extrapath,destinationzfile)
				print("🚀 重签名打包成功,请查看：%s" % destinationzfile)
			else:
				print("-----------------验签失败，请重试---------------")
		else:
			print("----------------签名失败，请重试----------------")
	finally:
		#关闭zipfile
		originzfile.close()
		#删除临时解压目录
		shutil.rmtree(extrapath)

if __name__ == '__main__':
	main()