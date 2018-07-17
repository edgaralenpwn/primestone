// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "threadinterrupt.h"

CThreadInterrupt::operator bool() const
{
    return flag.load(std::memory_order_acquire);
}

void CThreadInterrupt::reset()
{
    flag.store(false, std::memory_order_release);
}

void CThreadInterrupt::operator()()
{
    {
#ifndef WIN32
        std::unique_lock<std::mutex> lock(mut);
#else
	boost::unique_lock<boost::mutex> lock(mut);
#endif
        flag.store(true, std::memory_order_release);
    }
    cond.notify_all();
}

bool CThreadInterrupt::sleep_for(std::chrono::milliseconds rel_time)
{
#ifndef WIN32
    std::unique_lock<std::mutex> lock(mut);
    return !cond.wait_for(lock, rel_time, [this]() { return flag.load(std::memory_order_acquire); });
#else
    boost::chrono::milliseconds rel_time_boost = (boost::chrono::milliseconds)rel_time.count();
    boost::unique_lock<boost::mutex> lock(mut);
    return !cond.wait_for(lock, rel_time_boost, [this]() { return flag.load(std::memory_order_acquire); });
#endif

}

bool CThreadInterrupt::sleep_for(std::chrono::seconds rel_time)
{
    return sleep_for(std::chrono::duration_cast<std::chrono::milliseconds>(rel_time));
}

bool CThreadInterrupt::sleep_for(std::chrono::minutes rel_time)
{
    return sleep_for(std::chrono::duration_cast<std::chrono::milliseconds>(rel_time));
}
