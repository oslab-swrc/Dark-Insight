#include <linux/perf_event.h>
#include <linux/kernel.h>
//#include <linux/bitops.h>
#include <ring_buffer_shm.h>
#include "kdks_i.h"

#define perf_output_put_prb(prb, p, d) copy_data_to_prb(prb, p, &(d), sizeof(d))

/************************************************************
  how to copy perf event header and data to ringbuffer

  struct perf_event_header *header;
  struct perf_sample_data *data;
  struct perf_event *event;

  request_size = (size_t) header->size + sizeof(data->type);
  copy_size = copy_perf_data_to_prb(header, data, event);
*************************************************************/

static inline size_t copy_data_to_prb(struct ring_buffer_shm_t *prbshm,
	void *dest, const void *src, size_t size)
{
	/*No need to check return value for copy to prbshm*/
	copy_to_ring_buffer_shm(prbshm, dest , src, size);
	return size;
}

/*prbshm, req will be out*/
struct ring_buffer_shm_t *prb__alloc_buffer(struct ring_buffer_req_t *req, size_t len)
{
	int ret;
	struct ring_buffer_shm_t *prbshm = get_this_evbuf();

	if (!prbshm) {
		kdks_pr_trace(LOG_ERR, "Fail to get ring buffer shared memory \n");
		goto out;
	}

	/* allocate ring buffer to put data,
	   header->size included whole sampled data size + header*/
	ret = evbuf_put(prbshm, req, len);
	if (ret) {
		kdks_pr_trace(LOG_ERR, "Fail to allocate(put) sample data into prb, err : %d ,"
			"request size %lu\n", ret, len);
		prbshm = NULL;
	}
out:
	return prbshm;
}

/*copy data to prb and advance data pointer,
  return advanced data pointer*/
inline void *prb__copy_data(struct ring_buffer_shm_t *prbshm, void *dest,
	const void *src, size_t size)
{
	copy_to_ring_buffer_shm(prbshm, dest , src, size);
	return (void *)(dest + size);
}

/*copy collected data to ringbuffer,
  return: copied size*/
void prb__copy_done(struct ring_buffer_shm_t *prbshm, struct ring_buffer_req_t *req)
{
	evbuf_put_done(prbshm, req);
}

int copy_kdks_data_to_prb(struct kdks_sample_data *data)
{
	struct ring_buffer_shm_t *prbshm;
	struct ring_buffer_req_t req;
	size_t len = data->header.data_len;

	int cpu = smp_processor_id();

	prbshm = prb__alloc_buffer(&req, len);
	if (!prbshm)
		return -ENOMEM;

	prb__copy_data(prbshm, req.data, (const void *)data, len);
	prb__copy_done(prbshm, &req);
	kdks_pr_trace(LOG_DEBUG, "CPU:%d-prbshm free %lu, copy %lu\n",
		cpu, ring_buffer_shm_free_space(prbshm,0), len);
	return 0;
}

/*copy data to ringbuffer,
  return total copied data*/
size_t copy_perf_data_to_prb(struct perf_event_header *header,
	struct perf_sample_data *data, struct perf_event *event)
{
	int ret;
	struct ring_buffer_shm_t *prbshm = get_this_evbuf();
	struct ring_buffer_req_t req;
	u64 sample_type = data->type;
	struct perf_event_header *h;
	size_t len = 0;
	void *dest;

	/*XXX: in perf_output_sample is in NMI.
	  We shouldn't use any interrupt in kprobe handler to prevent deadlock
	  See more detail in pre_handler for kretprobe */
	if (!prbshm) {
		trace_printk("Fail to get ring buffer shared memory \n");
		return 0;
	}

	/*<--copy perf event header and data,
	  header->size is the total size of perf_event_sample */
	ret = evbuf_put(prbshm, &req, (size_t) header->size + sizeof(data->type));
	if (ret) {
		trace_printk("Fail to put data into ring buffer - request size %lu\n",
			(size_t) header->size + sizeof(data->type));
		return 0;
	}

	/*set copy destination and header location*/
	dest = req.data;
	h = (struct perf_event_header *) dest;

	/*copy header*/
	len += perf_output_put_prb(prbshm, dest, *header);

	/*copy sample_type */
	len += perf_output_put_prb(prbshm, dest+len, data->type);

	/*update header size for dks,
	  because we will copy perf sample type*/
	h->size += sizeof(data->type);

	/*we should keep this copy order*/
	if (sample_type & PERF_SAMPLE_IDENTIFIER)
		len += perf_output_put_prb(prbshm, dest+len, data->id);

	if (sample_type & PERF_SAMPLE_IP)
		len += perf_output_put_prb(prbshm, dest+len, data->ip);

	if (sample_type & PERF_SAMPLE_TID)
		len += perf_output_put_prb(prbshm, dest+len, data->tid_entry);

	if (sample_type & PERF_SAMPLE_TIME)
		len += perf_output_put_prb(prbshm, dest+len, data->time);

	if (sample_type & PERF_SAMPLE_ADDR)
		len += perf_output_put_prb(prbshm, dest+len, data->addr);

	if (sample_type & PERF_SAMPLE_ID)
		len += perf_output_put_prb(prbshm, dest+len, data->id);

	if (sample_type & PERF_SAMPLE_STREAM_ID)
		len += perf_output_put_prb(prbshm, dest+len, data->stream_id);

	if (sample_type & PERF_SAMPLE_CPU)
		len += perf_output_put_prb(prbshm, dest+len, data->cpu_entry);

	if (sample_type & PERF_SAMPLE_PERIOD) {
		len += perf_output_put_prb(prbshm, dest+len, data->period);
	}

	/*PERF_SAMPLE_READ - not supported*/
	if (sample_type & PERF_SAMPLE_READ)
		trace_printk("kdks : WARNING - PERF_SAMPLE_READ selected");

	if (sample_type & PERF_SAMPLE_CALLCHAIN) {
		if (data->callchain) {
			int size = 1;

			if (data->callchain)
				size += data->callchain->nr;

			size *= sizeof(u64);

			copy_to_ring_buffer_shm(prbshm, dest+len, data->callchain, size);
			len += size;

		} else {
			u64 nr = 0;
			len += perf_output_put_prb(prbshm, dest+len, nr);
		}
	}

	// Copy done! We don't need to copy after this.
	evbuf_put_done(prbshm, &req);
	return len;
}

struct perf_callchain_entry *perf_data_get_callchain(struct perf_sample_data *data)
{
	u64 sample_type = data->type;
	return likely(sample_type & PERF_SAMPLE_CALLCHAIN) ? data->callchain : ERR_PTR(-EINVAL);
}

pid_t perf_data_get_pid(struct perf_sample_data *data)
{
	u64 sample_type = data->type;
	return likely(sample_type & PERF_SAMPLE_TID) ? data->tid_entry.pid : KDKS_INVALID_PID;
}

/*get tglid from sample data*/
pid_t perf_data_get_tid(struct perf_sample_data *data)
{
	u64 sample_type = data->type;
	return likely(sample_type & PERF_SAMPLE_TID) ? data->tid_entry.tid : KDKS_INVALID_TID;
}

/*get time from sample data*/
u64 perf_data_get_time(struct perf_sample_data *data)
{
	u64 sample_type = data->type;
	return likely(sample_type & PERF_SAMPLE_TIME) ? data->time : KDKS_INVALID_TIME;
}

/* copy record info into kdks record temp buffer */
size_t copy_kdks_record(struct kdks_record *record, pid_t pid, pid_t tid, u64 waiting_time,
	callchain_t *ips, bool shipping_callchain)
{
	record->pid = pid;
	record->tid = tid;
	record->waiting_time = waiting_time;
	record->ips_id = (u64)ips;

	/*it doesn't shipped, copy it*/
	record->ips.nr = shipping_callchain ? ips->nr : 0;
	if (record->ips.nr)
		memcpy(&(record->ips.ip[0]), &(ips->ip[0]), sizeof(u64)*ips->nr);

	return (size_t)(sizeof__kdks_record(record->ips.nr));
}

