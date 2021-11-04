std::mutex mutex;

/**
 * Acquire the SpinLock; blocks the thread (by continuously polling the lock)
 * until the lock has been acquired.
 */
	void
SpinLock::lock()
{
	uint64_t startOfContention = 0;

	while (mutex.test_and_set(std::memory_order_acquire)) {
		if (startOfContention == 0) {
			startOfContention = Cycles::rdtsc();
			if (logWaits) {
				RAMCLOUD_TEST_LOG("Waiting on SpinLock");
			}
		} else {
			uint64_t now = Cycles::rdtsc();
			if (Cycles::toSeconds(now - startOfContention) > 1.0) {
				RAMCLOUD_LOG(WARNING,
						"%s SpinLock locked for one second; deadlock?",
						name.c_str());
				contendedTicks += now - startOfContention;
				startOfContention = now;
			}
		}
	}

	if (startOfContention != 0) {
		contendedTicks += (Cycles::rdtsc() - startOfContention);
		contendedAcquisitions++;
	}
	acquisitions++;
}
