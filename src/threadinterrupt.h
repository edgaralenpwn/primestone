// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THREADINTERRUPT_H
#define BITCOIN_THREADINTERRUPT_H

#include <atomic>
#include <chrono>
#ifndef WIN32
    #include <condition_variable>
    #include <mutex>
#else
    #include <boost/thread/win32/condition_variable.hpp>
    #include <boost/thread/win32/mutex.hpp>
#endif

/*
    A helper class for interruptible sleeps. Calling operator() will interrupt
    any current sleep, and after that point operator bool() will return true
    until reset.
*/
class CThreadInterrupt
{
public:
    explicit operator bool() const;
    void operator()();
    void reset();
    bool sleep_for(std::chrono::milliseconds rel_time);
    bool sleep_for(std::chrono::seconds rel_time);
    bool sleep_for(std::chrono::minutes rel_time);

private:
#ifndef WIN32
    std::condition_variable cond;
    std::mutex mut;
#else
    boost::condition_variable cond;
    boost::mutex mut;
#endif
    std::atomic<bool> flag;


};

#endif //BITCOIN_THREADINTERRUPT_H
