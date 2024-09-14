// elastic.h
#ifndef ELASTIC_H
#define ELASTIC_H

void SendLogToElastic(const char* log, unsigned long eventId);
void SendFileIntegrityLog(const char* fileName);
void SendComplianceReportToElastic(const char* reportPath);

#endif
