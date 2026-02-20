#pragma once
#include <iostream>
#include <Windows.h>
#include <string.h>

/*
  This class will be used as data structure
  to hold some important info about the user (victim).
*/

class Victim
{

private:
	char _computerName[MAX_COMPUTERNAME_LENGTH + 1];
	void _SetComputerNameVar() {
		DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
		GetComputerNameA(_computerName, &size);
	}

public:

	// Constructor
	Victim() {

	}

	// Destructor
	~Victim() {

	}

	/*
	  Victim related info:
	 */

	// initially set to false
	bool isPaid = false;

	std::string GetVictimID() {
		_SetComputerNameVar();
		return std::string(this->_computerName);
	}


};

