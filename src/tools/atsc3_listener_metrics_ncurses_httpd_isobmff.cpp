/*
 * atsc3_listener_metrics_ncurses_httpd_isobmff.c
 *
 *  Created on: Mar 17, 2019
 *      Author: jjustman
 *
 * NOTE: MPU-reassembly for MMT, TODO: move to MFU emmission to decoder buffer
 * 
 * global listener driver for LLS, MMT and ROUTE / DASH with refragmented http output on port 8889
 *
 *
 * note: to use local playback with ffmpeg as the box is building (since we dont interlave samples fully), use:
 * 	ffplay  cache:http://127.0.0.1:8889/video.m4s -loglevel trace
 *
 * autoplay watches service_id 5001 by default (set ATSC3_AUTOPLAY_SERVICE_ID to override);
 * tries MMT first, falls back to ROUTE/ALC (2026-09-20, since the original hardcoded
 * MMT-only/service_id=3 autoplay never fires on a ROUTE-only broadcast)
 *
 */


int PACKET_COUNTER=0;

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <ncurses.h>
#include <limits.h>
#include <strings.h>

#include "../bento4/ISOBMFFTrackJoiner.h"
#include "../atsc3_isobmff_tools.h"

#include "../atsc3_listener_udp.h"
#include "../atsc3_utils.h"
#include "../atsc3_logging_externs.h"


#include "../atsc3_lls.h"
#include "../atsc3_lls_alc_utils.h"

#include "../atsc3_lls_slt_parser.h"
#include "../atsc3_lls_sls_monitor_output_buffer_utils.h"

#include "../atsc3_mmtp_packet_types.h"
#include "../atsc3_mmtp_parser.h"
#include "../atsc3_ntp_utils.h"
#include "../atsc3_mmt_mpu_utils.h"
#include "../atsc3_mmt_reconstitution_from_media_sample.h"

#include "../atsc3_alc_rx.h"
#include "../atsc3_alc_utils.h"

#include "../atsc3_bandwidth_statistics.h"
#include "../atsc3_packet_statistics.h"

#include "../atsc3_output_statistics_ncurses.h"


#define _ENABLE_DEBUG true


//commandline stream filtering

uint32_t* dst_ip_addr_filter = NULL;
uint16_t* dst_ip_port_filter = NULL;
uint16_t* dst_packet_id_filter = NULL;

//jjustman-2019-09-18: refactored MMTP flow collection management
mmtp_flow_t* mmtp_flow;

//todo: jjustman-2019-09-18 refactor me out for mpu recon persitance
udp_flow_latest_mpu_sequence_number_container_t* udp_flow_latest_mpu_sequence_number_container;

// lls and alc glue for slt, contains lls_table_slt and lls_slt_alc_session
lls_slt_monitor_t* lls_slt_monitor;

extern atsc3_global_statistics_t* atsc3_global_statistics;

/**
 *
 * httpd listener integration
 *
 * jjustman-2019-09-18: TODO: refactor this out
 */


#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <dirent.h>
#include <microhttpd.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <algorithm>
#include <utility>

#define PORT 8889

#define FILENAME "test.mp4"
#define MIMETYPE "video/mp4"

#define PAGE "<html><head><title>File not found</title></head><body>File not found</body></html>"

//jjustman-2019-09-18 original code hardcoded MMT here; our target broadcast is ROUTE-only.
//Resolve whichever monitor (ALC/ROUTE or MMT) is actually active, so the HTTP path works for both.
static lls_sls_monitor_output_buffer_mode_t* get_active_output_buffer_mode() {
	if(lls_slt_monitor->lls_sls_alc_monitor) {
		return &lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode;
	}
	if(lls_slt_monitor->lls_sls_mmt_monitor) {
		return &lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode;
	}
	return NULL;
}

static ssize_t http_output_response_from_player_pipe_reader_callback (void *cls, uint64_t pos, char *buf, size_t max)
{
	/*
	 * 2026-09-20: this used to `return 0` from every "no data yet" branch
	 * below. libmicrohttpd's content-reader callback has no defined
	 * "nothing yet, call me again" return value - 0 is not
	 * MHD_CONTENT_READER_END_OF_STREAM (-1), but in practice MHD treated
	 * it as an early, clean end of the response anyway, which is exactly
	 * what caused a real crash: a client (mpv, over the HTTP restream)
	 * saw "End of file" and disconnected within seconds of connecting,
	 * right when total_fragments_incoming_written was still small (an
	 * ordinary startup race, not a real fault) - never fully returning
	 * a video stream once the buffer had actually caught up moments
	 * later. Retry in place instead, matching the same usleep-based
	 * back-pressure pattern already used on the write side
	 * (route_file_watcher_push_block_to_outputs) - only return once
	 * there's real data to hand back.
	 */
	while(true) {
		__INFO("http_output_response_from_player_pipe_reader_callback: enter: pos: %"PRIu64", buf: %p, max_size: %lu", pos, buf, max);

		lls_sls_monitor_output_buffer_mode_t* output_buffer_mode = get_active_output_buffer_mode();

		if(!output_buffer_mode) {
				__WARN("http_output_response_from_player_pipe_reader_callback: no active ALC or MMT monitor yet");
				//sleep so we don't spinlock too fast
				usleep(100000);
				continue;
			}
		if(!output_buffer_mode->http_output_buffer) {
			__WARN("http_output_response_from_player_pipe_reader_callback: not http_output_buffer yet");
			//sleep so we don't spinlock too fast
			usleep(100000);
			continue;
		}
		output_buffer_mode->http_output_buffer->http_output_conntected = true;
		if(!output_buffer_mode->http_output_buffer->http_payload_buffer_client_output &&
				!output_buffer_mode->http_output_buffer->http_payload_buffer_incoming) {
			__WARN("http_output_response_from_player_pipe_reader_callback: both buffers are null, retrying");
			//sleep so we don't spinlock too fast
			usleep(100000);
			continue;
		}
		//2026-09-20: this threshold assumes a real multi-item queue ("wait until several
		//are buffered before starting playback"). http_payload_buffer_incoming is a
		//single-slot mailbox, not a queue - route_file_watcher_run_thread already
		//blocks each push until the previous one is consumed, so there's nothing to
		//gain by waiting here, and with a threshold > 1 it deadlocks: the writer won't
		//push item 2 until item 1 is read, but the reader won't read item 1 until 4
		//items have been written.
		if(!output_buffer_mode->http_output_buffer->http_payload_buffer_client_output &&
				output_buffer_mode->http_output_buffer->total_fragments_incoming_written < 1) {
				__WARN("http_output_response_from_player_pipe_reader_callback: no fragments written yet, retrying");
				//sleep so we don't spinlock too fast
				usleep(100000);
				continue;
			}

		lls_sls_monitor_reader_mutex_lock(output_buffer_mode->http_output_buffer->http_payload_buffer_mutex);
		//swap
		if(!output_buffer_mode->http_output_buffer->http_payload_buffer_client_output && output_buffer_mode->http_output_buffer->http_payload_buffer_incoming) {
			output_buffer_mode->http_output_buffer->http_payload_buffer_client_output = output_buffer_mode->http_output_buffer->http_payload_buffer_incoming;
			output_buffer_mode->http_output_buffer->http_payload_buffer_incoming = NULL;
			output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->i_pos = 0;
		}

		//2026-09-20: the checks above this mutex are unprotected reads, so a second
		//concurrent connection (real segfault seen tonight: two ffplay connections
		//racing on the same single-slot buffer via MHD_USE_THREAD_PER_CONNECTION) can
		//get past them, then find both client_output and incoming NULL by the time it
		//reaches here (the other connection's thread having just consumed and freed
		//the only available block). This buffer is fundamentally single-client -
		//retry instead of dereferencing NULL.
		if(!output_buffer_mode->http_output_buffer->http_payload_buffer_client_output) {
			lls_sls_monitor_reader_mutex_unlock(output_buffer_mode->http_output_buffer->http_payload_buffer_mutex);
			usleep(100000);
			continue;
		}

		//block copy accordingly
		uint32_t block_pos = output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->i_pos;
		uint32_t block_size = __MIN(max, output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->p_size - output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->i_pos);

		__INFO("http_output_response_from_player_pipe_reader_callback: copying from %p, block_pos (i_pos): %u, block_size: %u, p_size: %u",
				output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->p_buffer,
				block_pos,
				block_size,
				output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->p_size);



		memcpy(buf, &output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->p_buffer
				[block_pos], block_size);
		output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->i_pos += block_size;

		if(output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->i_pos == output_buffer_mode->http_output_buffer->http_payload_buffer_client_output->p_size) {
			__INFO("http_output_response_from_player_pipe_reader_callback: end of output buffer, setting null");
			block_Release(&output_buffer_mode->http_output_buffer->http_payload_buffer_client_output);

		}

		lls_sls_monitor_reader_mutex_unlock(output_buffer_mode->http_output_buffer->http_payload_buffer_mutex);

		__INFO("http_output_response_from_player_pipe_reader_callback: return: returning size: %u, total incoming fragments written: %u", block_size, output_buffer_mode->http_output_buffer->total_fragments_incoming_written);

		return block_size;
	}
}


static void http_output_response_from_player_pipe_reader_free_callback (void *cls)
{
	lls_sls_monitor_output_buffer_mode_t* output_buffer_mode = get_active_output_buffer_mode();
	if(output_buffer_mode && output_buffer_mode->http_output_buffer) {
		output_buffer_mode->http_output_buffer->http_output_conntected = false;
	}
	__INFO("http_output_response_from_player_pipe_reader_free_callback: closing: %p", cls);
}


static enum MHD_Result http_output_response_from_player_pipe (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data,
	  size_t *upload_data_size, void **ptr)
{
	static int aptr;
	struct MHD_Response *response;
	enum MHD_Result ret;
	FILE *file;
	int fd;
	//  DIR *dir;
	struct stat buf;
	char emsg[1024];
	(void)cls;               /* Unused. Silent compiler warning. */
	(void)version;           /* Unused. Silent compiler warning. */
	(void)upload_data;       /* Unused. Silent compiler warning. */
	(void)upload_data_size;  /* Unused. Silent compiler warning. */

	if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
	return MHD_NO;              /* unexpected method */

  	response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN, 512 * 1024,     /* 512k page size */
                                                    &http_output_response_from_player_pipe_reader_callback,
                                                    NULL,
                                                    &http_output_response_from_player_pipe_reader_free_callback);

	if (NULL == response){
		return MHD_NO;
	}
	MHD_add_response_header(response, "Content-Type", MIMETYPE);

	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	//not sure if this is needed here or not..
	MHD_destroy_response (response);

	return ret;
}

//jjustman-2019-09-18 original code only ever looked for an MMT session on a
//hardcoded service_id of 3. Our target broadcast (Buffalo NY / Sinclair, 485MHz)
//is ROUTE-only - no MMT anywhere on the mux - so that loop spun forever and
//never set up the output/http buffers. Try MMT first (unchanged behavior for
//2026-09-20: push a real on-disk fragment's bytes into both the local ffplay
//pipe and the HTTP output buffer. Mirrors the locking pattern already used
//elsewhere for each buffer (pipe_buffer_reader_mutex_lock/unlock + semaphore
//post for ffplay; lls_sls_monitor_reader_mutex_lock/unlock for http).
static void route_file_watcher_push_block_to_outputs(block_t* content_block) {
    if(!lls_slt_monitor->lls_sls_alc_monitor || !content_block) {
        return;
    }
    lls_sls_monitor_output_buffer_mode_t* output_buffer_mode = &lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode;

    if(output_buffer_mode->ffplay_output_enabled && output_buffer_mode->pipe_ffplay_buffer) {
        pipe_ffplay_buffer_t* pipe_ffplay_buffer = output_buffer_mode->pipe_ffplay_buffer;
        pipe_buffer_reader_mutex_lock(pipe_ffplay_buffer);
        pipe_buffer_unsafe_push_block(pipe_ffplay_buffer, content_block->p_buffer, content_block->p_size);
        pipe_buffer_notify_semaphore_post(pipe_ffplay_buffer);
        lls_slt_monitor_check_and_handle_pipe_ffplay_buffer_is_shutdown(lls_slt_monitor);
        pipe_buffer_reader_mutex_unlock(pipe_ffplay_buffer);
    }

    if(output_buffer_mode->http_output_enabled && output_buffer_mode->http_output_buffer) {
        http_output_buffer_t* http_output_buffer = output_buffer_mode->http_output_buffer;

        //2026-09-20: http_payload_buffer_incoming is a single-slot mailbox, not a queue.
        //Pushing a new fragment before the reader callback has consumed the previous one
        //(swapped it into http_payload_buffer_client_output) silently block_Destroy()s
        //and drops it - including, fatally, the init segment itself, since a burst of
        //already-completed fragments on disk gets pushed with no delay between them.
        //Block here until the previous one is actually picked up, so delivery to
        //whichever client is connected is complete and in order.
        while(true) {
            lls_sls_monitor_reader_mutex_lock(http_output_buffer->http_payload_buffer_mutex);
            bool slot_free = !http_output_buffer->http_payload_buffer_incoming;
            if(slot_free) {
                http_output_buffer->http_payload_buffer_incoming = block_Duplicate(content_block);
                http_output_buffer->total_fragments_incoming_written++;
            }
            lls_sls_monitor_reader_mutex_unlock(http_output_buffer->http_payload_buffer_mutex);
            if(slot_free) {
                break;
            }
            usleep(50000);
        }
    }
}

//2026-09-20: the "real" TSI-flow-to-buffer bridge (has_written_init_box /
//should_flush_output_buffer, copy_video_init_block/copy_video_fragment_block)
//is never wired up anywhere in this codebase (confirmed: zero callers for any
//of it). But atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback
//DOES really work (once file_dump_enabled + certification_data are set - see
//global_autoplay_run_thread below) and writes complete, valid, playable
//ISOBMFF init/fragment files straight to route/<service_id>/ as real ROUTE
//objects complete - see stsid.sls's afdt:fileTemplate for the naming
//convention per flow. This thread bypasses the broken bridge entirely: watch
//that directory for a chosen track's init segment + newly-arriving fragments
//and push their real bytes directly into the ffplay pipe / http buffer.
//Video (TSI 100 on this mux) doesn't work this way yet - real objects are ~2-3%
//short of complete before giving up (no working FEC/repair-symbol recovery for
//this large an object), so this currently only carries audio successfully.
//Prefix/service_id are configurable via ATSC3_AUTOPLAY_TRACK_PREFIX (default
//"a0-a02_2-", the first audio track) and ATSC3_AUTOPLAY_SERVICE_ID.
void* route_file_watcher_run_thread(void* p) {
    while(!lls_slt_monitor->lls_sls_alc_monitor || !lls_slt_monitor->lls_sls_alc_monitor->atsc3_lls_slt_service) {
        sleep(1);
    }
    //give the persistence pipeline a head start so at least the init segment exists
    sleep(5);

    uint16_t service_id = lls_slt_monitor->lls_sls_alc_monitor->atsc3_lls_slt_service->service_id;
    const char* prefix_env = getenv("ATSC3_AUTOPLAY_TRACK_PREFIX");
    std::string prefix = prefix_env ? prefix_env : "a0-a02_2-";

    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "route/%u", service_id);

    std::string init_path = std::string(dir_path) + "/" + prefix + "init.mp4";

    /*
     * 2026-09-25: briefly rewrote this to watch a completely different
     * output path (lls_sls_monitor_output_buffer_alc_file_dump()'s flat
     * route/<seq>.a|.v files) after finding that alc_file_dump() call site
     * gated on has_written_init_box/should_flush_output_buffer, which are
     * never set true anywhere in this codebase. Reverted: that bridge was
     * ALREADY known-dead per the 2026-09-20 comment below this function -
     * the ACTUAL working writer is
     * atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback,
     * which does write real route/<service_id>/<prefix><TOI>.<ext> files
     * matching exactly what this original logic already watches for. The
     * reason ATSC3_AUTOPLAY_TRACK_PREFIX=video- never produces anything is
     * upstream of this watcher: video objects on this mux arrive ~2-3%
     * short of complete and so never reach "complete" for any writer to
     * persist. The shortfall is NOT settled as broadcast loss - the vendor
     * app plays this mux cleanly, and atsc3-player.py's missing objects
     * turned out to be its own reassembly bug - so still investigate.
     */
    __INFO("route_file_watcher_run_thread: watching dir: %s, prefix: %s, waiting for init segment: %s",
           dir_path, prefix.c_str(), init_path.c_str());

    struct stat st;
    while(stat(init_path.c_str(), &st) != 0) {
        sleep(1);
    }

    block_t* init_block = block_Read_from_filename(init_path.c_str());
    if(init_block) {
        __INFO("route_file_watcher_run_thread: pushing init segment: %s, size: %d", init_path.c_str(), init_block->p_size);
        route_file_watcher_push_block_to_outputs(init_block);
        block_Destroy(&init_block);
    } else {
        __ERROR("route_file_watcher_run_thread: unable to read init segment: %s", init_path.c_str());
    }

    long last_toi_pushed = -1;

    /*
     * 2026-09-20: starting last_toi_pushed at -1 with no floor meant every
     * fresh process start (and this tool has been restarted many times per
     * session, with nothing ever deleting old fragments) replayed the
     * *entire* accumulated backlog from the beginning before ever catching
     * up to live - a real bug, not just disk bloat, confirmed live: "it's
     * playing stuff from over an hour ago". Do one scan up front and skip
     * to near the highest TOI already on disk minus a small buffer, so
     * startup begins close to the live edge instead of replaying history.
     */
    {
        std::vector<long> existing_tois;
        DIR* d = opendir(dir_path);
        if(d) {
            struct dirent* entry;
            while((entry = readdir(d))) {
                std::string name = entry->d_name;
                if(name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
                    size_t dot_pos = name.find('.', prefix.size());
                    if(dot_pos != std::string::npos) {
                        std::string toi_str = name.substr(prefix.size(), dot_pos - prefix.size());
                        bool all_digit = !toi_str.empty();
                        for(size_t i = 0; i < toi_str.size() && all_digit; i++) {
                            if(!isdigit((unsigned char)toi_str[i])) all_digit = false;
                        }
                        if(all_digit) {
                            existing_tois.push_back(atol(toi_str.c_str()));
                        }
                    }
                }
            }
            closedir(d);
        }
        if(!existing_tois.empty()) {
            long max_toi = *std::max_element(existing_tois.begin(), existing_tois.end());
            const long __STARTUP_LIVE_EDGE_BACKLOG = 5;
            last_toi_pushed = __MAX(-1L, max_toi - __STARTUP_LIVE_EDGE_BACKLOG);
            __INFO("route_file_watcher_run_thread: skipping backlog on startup, max_toi on disk: %ld, starting from: %ld", max_toi, last_toi_pushed);
        }
    }

    time_t last_cleanup_time = 0;
    //2026-09-20: user-requested - nothing ever deleted old fragments, so disk
    //usage grows unbounded over a long-running session. Age-based (not
    //TOI-based) so it applies uniformly to every track's files in this
    //directory (video/audio/subtitle each use different prefixes/extensions),
    //not just the one this thread happens to be watching.
    const time_t __FRAGMENT_RETENTION_SECONDS = 300;
    const time_t __CLEANUP_INTERVAL_SECONDS = 60;

    while(true) {
        //2026-09-20: different flows use different fragment extensions per their
        //own afdt:fileTemplate (audio: .m4s, video: .mp4v) - match the numeric TOI
        //regardless of extension and keep the real filename, rather than assuming .m4s.
        std::vector<std::pair<long, std::string>> tois;
        DIR* d = opendir(dir_path);
        if(d) {
            struct dirent* entry;
            while((entry = readdir(d))) {
                std::string name = entry->d_name;
                if(name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
                    size_t dot_pos = name.find('.', prefix.size());
                    if(dot_pos != std::string::npos) {
                        std::string toi_str = name.substr(prefix.size(), dot_pos - prefix.size());
                        bool all_digit = !toi_str.empty();
                        for(size_t i = 0; i < toi_str.size() && all_digit; i++) {
                            if(!isdigit((unsigned char)toi_str[i])) all_digit = false;
                        }
                        if(all_digit) {
                            tois.push_back(std::make_pair(atol(toi_str.c_str()), name));
                        }
                    }
                }
            }
            closedir(d);
        }
        std::sort(tois.begin(), tois.end());

        for(size_t i = 0; i < tois.size(); i++) {
            if(tois[i].first > last_toi_pushed) {
                char frag_path[512];
                snprintf(frag_path, sizeof(frag_path), "%s/%s", dir_path, tois[i].second.c_str());
                block_t* frag_block = block_Read_from_filename(frag_path);
                if(frag_block) {
                    __INFO("route_file_watcher_run_thread: pushing fragment: %s, size: %d", frag_path, frag_block->p_size);
                    route_file_watcher_push_block_to_outputs(frag_block);
                    block_Destroy(&frag_block);
                    last_toi_pushed = tois[i].first;
                } else {
                    __WARN("route_file_watcher_run_thread: unable to read fragment (may still be mid-write): %s", frag_path);
                }
            }
        }

        time_t now = time(NULL);
        if(now - last_cleanup_time >= __CLEANUP_INTERVAL_SECONDS) {
            last_cleanup_time = now;
            int cleaned = 0;
            DIR* cleanup_d = opendir(dir_path);
            if(cleanup_d) {
                struct dirent* entry;
                while((entry = readdir(cleanup_d))) {
                    std::string name = entry->d_name;
                    if(name == "." || name == "..") continue;
                    //never delete init segments - they're small, needed for
                    //the lifetime of the process, and not part of the churn
                    if(name.find("init.mp4") != std::string::npos) continue;
                    char full_path[512];
                    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name.c_str());
                    struct stat cleanup_st;
                    if(stat(full_path, &cleanup_st) == 0 && (now - cleanup_st.st_mtime) > __FRAGMENT_RETENTION_SECONDS) {
                        if(unlink(full_path) == 0) {
                            cleaned++;
                        }
                    }
                }
                closedir(cleanup_d);
            }
            if(cleaned) {
                __INFO("route_file_watcher_run_thread: cleanup pass removed %d fragment(s) older than %lds from %s", cleaned, __FRAGMENT_RETENTION_SECONDS, dir_path);
            }
        }

        sleep(1);
    }

    return NULL;
}

//jjustman-2019-09-18 original code only ever looked for an MMT session on a
//hardcoded service_id of 3. Our target broadcast (Buffalo NY / Sinclair, 485MHz)
//is ROUTE-only - no MMT anywhere on the mux - so that loop spun forever and
//never set up the output/http buffers. Try MMT first (unchanged behavior for
//any MMT broadcast), then fall back to ROUTE/ALC using the same session
//resolution the interactive ncurses tool's 's' key handler already uses
//successfully (atsc3_output_statistics_ncurses.c) - the "official" ALC
//session vector is never populated anywhere in this codebase, so we build
//the session directly from the SLT's own already-parsed broadcast_svc_signalling.
//Service id is configurable via ATSC3_AUTOPLAY_SERVICE_ID env var (default 5001,
//WNYO on this mux) instead of the old hardcoded 3.
void* global_autoplay_run_thread(void*p) {
    uint16_t my_service_id = 5001;
    const char* service_id_env = getenv("ATSC3_AUTOPLAY_SERVICE_ID");
    if(service_id_env) {
        my_service_id = (uint16_t) atoi(service_id_env);
    }
    __INFO("global_autoplay_run_thread: watching for service_id: %u (set ATSC3_AUTOPLAY_SERVICE_ID to override)", my_service_id);

    lls_sls_mmt_monitor_t* lls_sls_mmt_monitor = NULL;

    while(true) {
        sleep(1);
        lls_sls_mmt_session_t* lls_sls_mmt_session = lls_slt_mmt_session_find_from_service_id(lls_slt_monitor, my_service_id);
        if(lls_sls_mmt_session) {
            lls_sls_mmt_monitor = lls_sls_mmt_monitor_create();
            lls_sls_mmt_monitor->transients.lls_mmt_session = lls_sls_mmt_session;
            //TODO - jjustman-2019-10-03 - fix this hack
            lls_sls_mmt_monitor->transients.atsc3_lls_slt_service = lls_sls_mmt_session->atsc3_lls_slt_service;

//            lls_sls_mmt_monitor->video_packet_id = lls_sls_mmt_session->video_packet_id;
//            lls_sls_mmt_monitor->audio_packet_id = lls_sls_mmt_session->audio_packet_id;

            lls_sls_mmt_monitor->lls_sls_monitor_output_buffer.has_written_init_box = false;
            lls_slt_monitor->lls_sls_mmt_monitor = lls_sls_mmt_monitor;
            sleep(3);

            lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode.pipe_ffplay_buffer = pipe_create_ffplay_resolve_fps(&lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff);

            lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode.ffplay_output_enabled = true;

            lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode.http_output_buffer = (http_output_buffer_t*)calloc(1, sizeof(http_output_buffer_t));
            lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode.http_output_buffer->http_payload_buffer_mutex = lls_sls_monitor_reader_mutext_create();
            lls_slt_monitor->lls_sls_mmt_monitor->lls_sls_monitor_output_buffer_mode.http_output_enabled = true;
            break;
        }

        //no MMT session for this service_id - try resolving a ROUTE/ALC session instead
        lls_sls_alc_session_t* lls_sls_alc_session = lls_slt_alc_session_find_from_service_id(lls_slt_monitor, my_service_id);

        if(!lls_sls_alc_session) {
            atsc3_lls_slt_service_t* atsc3_lls_slt_service_for_session =
                lls_slt_monitor_find_lls_slt_service_id_group_id_cache_entry(lls_slt_monitor, my_service_id);

            if(atsc3_lls_slt_service_for_session) {
                for(int svc_sig_i = 0; svc_sig_i < atsc3_lls_slt_service_for_session->atsc3_slt_broadcast_svc_signalling_v.count; svc_sig_i++) {
                    atsc3_slt_broadcast_svc_signalling_t* svc_signalling =
                        atsc3_lls_slt_service_for_session->atsc3_slt_broadcast_svc_signalling_v.data[svc_sig_i];

                    if(svc_signalling && svc_signalling->sls_destination_ip_address && svc_signalling->sls_destination_udp_port) {
                        uint32_t dest_ip = parseIpAddressIntoIntval(svc_signalling->sls_destination_ip_address);
                        uint16_t dest_port = (uint16_t) atoi(svc_signalling->sls_destination_udp_port);
                        uint32_t source_ip = svc_signalling->sls_source_ip_address ?
                            parseIpAddressIntoIntval(svc_signalling->sls_source_ip_address) : 0;

                        lls_sls_alc_session = lls_slt_alc_session_find_or_create_from_ip_udp_values(
                            lls_slt_monitor, atsc3_lls_slt_service_for_session, dest_ip, dest_port, source_ip);
                        break;
                    }
                }
            }
        }

        if(lls_sls_alc_session) {
            __INFO("global_autoplay_run_thread: resolved ROUTE/ALC session for service_id: %u", my_service_id);

            lls_sls_alc_monitor_t* lls_sls_alc_monitor = lls_sls_alc_monitor_create();
            lls_sls_alc_monitor->lls_alc_session = lls_sls_alc_session;
            lls_sls_alc_monitor->atsc3_lls_slt_service = lls_sls_alc_session->atsc3_lls_slt_service;
            lls_sls_alc_monitor->lls_sls_monitor_output_buffer.has_written_init_box = false;
            lls_slt_monitor->lls_sls_alc_monitor = lls_sls_alc_monitor;
            sleep(3);

            //2026-09-20: atsc3_lls_slt_monitor_update_monitors_from_latest_certification_data_table()
            //only wires this up for monitors registered in lls_sls_alc_monitor_v - our monitor is a
            //standalone one assigned directly to lls_slt_monitor->lls_sls_alc_monitor, so it's invisible
            //to that mechanism. Without this, atsc3_cms_validate_from_context() always fails immediately
            //(transients.atsc3_certification_data NULL), which silently blocks all ALC object completion
            //processing (signaling AND media) via atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback.
            if(lls_slt_monitor->lls_latest_certification_data_table) {
                lls_slt_monitor->lls_sls_alc_monitor->transients.atsc3_certification_data = &lls_slt_monitor->lls_latest_certification_data_table->certification_data;
            } else {
                __WARN("global_autoplay_run_thread: lls_latest_certification_data_table not yet available, CMS/smime validation will fail until it arrives");
            }

            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.pipe_ffplay_buffer = pipe_create_ffplay_resolve_fps(&lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff);

            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.ffplay_output_enabled = true;

            //2026-09-20: atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback()
            //bails out immediately unless this is set - without it, NOTHING in the ALC object
            //completion/persistence pipeline ever runs, for any object type, video included.
            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.file_dump_enabled = true;

            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.http_output_buffer = (http_output_buffer_t*)calloc(1, sizeof(http_output_buffer_t));
            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.http_output_buffer->http_payload_buffer_mutex = lls_sls_monitor_reader_mutext_create();
            lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.http_output_enabled = true;
            break;
        }
    }

    return NULL;
}

void* global_httpd_run_thread(void* lls_slt_monitor_ptr) {

//
//    lls_slt_monitor_t* lls_slt_monitor = (lls_slt_monitor_t*)lls_slt_monitor_ptr;
//    lls_sls_mmt_monitor_t* lls_sls_mmt_monitor = NULL;
//    lls_sls_alc_monitor* lls_sls_alc_monitor = NULL;

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
                           PORT,
                           NULL, NULL, &http_output_response_from_player_pipe, (void*)PAGE, MHD_OPTION_END);

    if (NULL == daemon) return NULL;
    MHD_run(daemon);

    while(true) {
    	sleep(1);
    }
}


void count_packet_as_filtered(udp_packet_t* udp_packet) {
	atsc3_global_statistics->packet_counter_filtered_ipv4++;
	global_bandwidth_statistics->interval_filtered_current_bytes_rx += udp_packet->data->p_size;
	global_bandwidth_statistics->interval_filtered_current_packets_rx++;
}

void update_global_mmtp_statistics_from_udp_packet_t(lls_sls_mmt_session_t* matching_lls_sls_mmt_session, udp_packet_t *udp_packet) {
	global_bandwidth_statistics->interval_mmt_current_bytes_rx += udp_packet->data->p_size;

	mmtp_packet_header_t* mmtp_packet_header = mmtp_packet_header_parse_from_block_t(udp_packet->data);

	if(!mmtp_packet_header) {
		goto error;
	}

	//for filtering MMT flows by a specific packet_id
	if(dst_packet_id_filter && *dst_packet_id_filter != mmtp_packet_header->mmtp_packet_id) {
		count_packet_as_filtered(udp_packet);

		goto cleanup;
	}

	if(mmtp_packet_header->mmtp_payload_type == 0x0) {
		mmtp_mpu_packet_t* mmtp_mpu_packet = mmtp_mpu_packet_parse_from_block_t(mmtp_packet_header, udp_packet->data);
		if(!mmtp_mpu_packet) {
			goto error;
		}

		if(mmtp_mpu_packet->mpu_timed_flag == 1) {
		    atsc3_packet_statistics_mmt_stats_populate(udp_packet, mmtp_mpu_packet);
            mmtp_mpu_packet = mmtp_process_from_payload(mmtp_mpu_packet, mmtp_flow, lls_slt_monitor, udp_packet, udp_flow_latest_mpu_sequence_number_container, matching_lls_sls_mmt_session);

		} else {
			//non-timed
			__ATSC3_WARN("update_global_mmtp_statistics_from_udp_packet_t: mmtp_packet_header_parse_from_block_t - non-timed payload: packet_id: %u", mmtp_packet_header->mmtp_packet_id);
		}
	} else if(mmtp_packet_header->mmtp_payload_type == 0x2) {

		mmtp_signalling_packet_t* mmtp_signalling_packet = mmtp_signalling_packet_parse_and_free_packet_header_from_block_t(&mmtp_packet_header, udp_packet->data);
		uint8_t parsed_count = mmt_signalling_message_parse_packet(mmtp_signalling_packet, udp_packet->data);
		if(parsed_count) {
			mmt_signalling_message_dump(mmtp_signalling_packet);
			//temp hack until we are managing flows better
			    /* keep this packet around for processing **/
            //assign our mmtp_mpu_packet to asset/packet_id/mpu_sequence_number flow
            mmtp_asset_flow_t* mmtp_asset_flow = mmtp_flow_find_or_create_from_udp_packet(mmtp_flow, udp_packet);
            mmtp_asset_t* mmtp_asset = mmtp_asset_flow_find_or_create_asset_from_lls_sls_mmt_session(mmtp_asset_flow, matching_lls_sls_mmt_session);
           
            //TODO: FIX ME!!! HACK - jjustman-2019-09-05
            mmtp_mpu_packet_t* mmtp_mpu_packet = mmtp_mpu_packet_new();
            mmtp_mpu_packet->mmtp_packet_id = mmtp_signalling_packet->mmtp_packet_id;
            
            mmtp_packet_id_packets_container_t* mmtp_packet_id_packets_container = mmtp_asset_find_or_create_packets_container_from_mmt_mpu_packet(mmtp_asset, mmtp_mpu_packet);
            mmtp_packet_id_packets_container_add_mmtp_signalling_packet(mmtp_packet_id_packets_container, mmtp_signalling_packet);
            
            //TODO: FIX ME!!! HACK - jjustman-2019-09-05
            mmtp_mpu_packet_free(&mmtp_mpu_packet);
            
            //update our sls_mmt_session info
            mmt_signalling_message_update_lls_sls_mmt_session(mmtp_signalling_packet, matching_lls_sls_mmt_session);
 
		} else {
            //jjustman-2019-09-05 - unsupported signalling message type, so free immediately
            mmtp_signalling_packet_free(&mmtp_signalling_packet);

			goto error;
		}

	} else {
		__ATSC3_WARN("update_global_mmtp_statistics_from_udp_packet_t: unknown payload type of 0x%x", mmtp_packet_header->mmtp_payload_type);
		goto error;
	}
    
    atsc3_global_statistics->packet_counter_mmtp_packets_received++;
    global_bandwidth_statistics->interval_mmt_current_packets_rx++;

    goto cleanup;

 error:
	atsc3_global_statistics->packet_counter_mmtp_packets_parsed_error++;
		__ERROR("update_global_mmtp_statistics_from_udp_packet_t: raw packet ptr is null, parsing failed for flow: %d.%d.%d.%d:(%-10u):%-5u \t ->  %d.%d.%d.%d:(%-10u):%-5u ",
				__toipandportnonstruct(udp_packet->udp_flow.src_ip_addr, udp_packet->udp_flow.src_port),
				udp_packet->udp_flow.src_ip_addr,
				__toipandportnonstruct(udp_packet->udp_flow.dst_ip_addr, udp_packet->udp_flow.dst_port),
				udp_packet->udp_flow.dst_ip_addr);
    
 cleanup:
    if(mmtp_packet_header) {
        mmtp_packet_header_free(&mmtp_packet_header);
    }
}

/**
 * only build our atsc3_isobmff_build_joined_alc_isobmff_fragment if we have ffplay output active
 *
 * TODO: jjustman-2020-06-02: fixme to use proper lls_alc monitor pattern
 */

static void route_process_from_alc_packet(udp_flow_t* udp_flow, atsc3_alc_packet_t **alc_packet) {
	/**
	 * jdj-2019-05-29: TODO - refactor out for EXT_FTI processing that may be missing a close object flag,
	 * 							 use a sparse array lookup (https://github.com/ned14/nedtries) for resolution to proper transfer_object_length to back-patch close flag
	 *
	 * 							 &&
				atsc3_sls_alc_flow_get_first_tsi(&lls_slt_monitor->lls_sls_alc_monitor->atsc3_sls_alc_video_flow_v) &&
				atsc3_sls_alc_flow_get_first_tsi(&lls_slt_monitor->lls_sls_alc_monitor->atsc3_sls_alc_audio_flow_v)
	 */
	if((*alc_packet)->use_start_offset && lls_slt_monitor->lls_sls_alc_monitor) {



		atsc3_route_object_t* atsc3_route_object = atsc3_alc_persist_route_object_lct_packet_received_for_lls_sls_alc_monitor_all_flows(*alc_packet, lls_slt_monitor->lls_sls_alc_monitor);



		atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback(udp_flow,
                                                                                *alc_packet,
                                                                                lls_slt_monitor->lls_sls_alc_monitor, atsc3_route_object);
	}
    
    if(lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer.has_written_init_box && lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer.should_flush_output_buffer) {

    	lls_sls_monitor_output_buffer_t* lls_sls_monitor_output_buffer_final_muxed_payload = atsc3_isobmff_build_joined_alc_isobmff_fragment(&lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer);

		if(!lls_sls_monitor_output_buffer_final_muxed_payload) {
			lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer.should_flush_output_buffer = false;
			__ERROR("lls_sls_monitor_output_buffer_final_muxed_payload was NULL!");
			return;
		}

        if(lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.ffplay_output_enabled && lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.pipe_ffplay_buffer) {

        	pipe_ffplay_buffer_t* pipe_ffplay_buffer = lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.pipe_ffplay_buffer;

        	pipe_buffer_reader_mutex_lock(pipe_ffplay_buffer);

        	pipe_buffer_unsafe_push_block(pipe_ffplay_buffer, lls_sls_monitor_output_buffer_final_muxed_payload->joined_isobmff_block->p_buffer, lls_sls_monitor_output_buffer_final_muxed_payload->joined_isobmff_block->i_pos);

        	pipe_buffer_notify_semaphore_post(pipe_ffplay_buffer);

			//check to see if we have shutdown
			lls_slt_monitor_check_and_handle_pipe_ffplay_buffer_is_shutdown(lls_slt_monitor);

			pipe_buffer_reader_mutex_unlock(pipe_ffplay_buffer);
			//reset our buffer pos and should_flush = false;
        }

		//2026-09-20: this half of the pipeline (HTTP remote delivery) never existed even
		//commented-out - the original author only ever wired the local ffplay pipe above.
		//Mirror the same push into http_output_buffer so a remote client (ffplay/VLC over
		//http://<host>:8889/) gets the same joined ISOBMFF fragments.
		http_output_buffer_t* http_output_buffer = lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.http_output_buffer;
		if(lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.http_output_enabled && http_output_buffer) {

			lls_sls_monitor_reader_mutex_lock(http_output_buffer->http_payload_buffer_mutex);

			if(http_output_buffer->http_payload_buffer_incoming) {
				//previous fragment wasn't picked up by the reader callback yet - drop it
				//in favor of the newest one rather than let unbounded backlog build up
				block_Destroy(&http_output_buffer->http_payload_buffer_incoming);
			}
			http_output_buffer->http_payload_buffer_incoming = block_Duplicate(lls_sls_monitor_output_buffer_final_muxed_payload->joined_isobmff_block);
			http_output_buffer->total_fragments_incoming_written++;

			lls_sls_monitor_reader_mutex_unlock(http_output_buffer->http_payload_buffer_mutex);
		}

        if(true || lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.file_dump_enabled) {
        	//don't double write to disk for route objects as we do this already in the route alc refrag client
            lls_sls_monitor_output_buffer_alc_file_dump(lls_sls_monitor_output_buffer_final_muxed_payload, "route/",
            		lls_slt_monitor->lls_sls_alc_monitor->last_completed_flushed_audio_toi,
					lls_slt_monitor->lls_sls_alc_monitor->last_completed_flushed_video_toi);
        }

		lls_sls_monitor_output_buffer_reset_moof_and_fragment_position(&lls_slt_monitor->lls_sls_alc_monitor->lls_sls_monitor_output_buffer);
    }
}

atsc3_alc_packet_t* route_parse_from_udp_packet(lls_sls_alc_session_t *matching_lls_slt_alc_session, udp_packet_t *udp_packet) {
    atsc3_alc_packet_t* alc_packet = NULL;

    //sanity check
    if(matching_lls_slt_alc_session->alc_session) {
        //re-inject our alc session

        //process ALC streams
        int retval = alc_rx_analyze_packet_a331_compliant((char*)block_Get(udp_packet->data), block_Remaining_size(udp_packet->data), &alc_packet);
        if(!retval) {
            atsc3_global_statistics->packet_counter_alc_packets_parsed++;
            
            //don't dump unless this is pointing to our monitor session
            if(lls_slt_monitor->lls_sls_alc_monitor &&  lls_slt_monitor->lls_sls_alc_monitor->lls_alc_session && lls_slt_monitor->lls_sls_alc_monitor->lls_alc_session->service_id == matching_lls_slt_alc_session->service_id) {
                goto ret;
            } else {
               // __ATSC3_TRACE("ignoring service_id: %u", matching_lls_slt_alc_session->service_id);
            }
            goto cleanup;
        } else {
            __ERROR("Error in ALC decode: %d", retval);
            atsc3_global_statistics->packet_counter_alc_packets_parsed_error++;
            goto cleanup;
        }
    } else {
        __WARN("Have matching ALC session information but ALC client is not active!");
        goto cleanup;
    }
cleanup:
    alc_packet_free(&alc_packet);
    alc_packet = NULL;

ret:
    return alc_packet;
    
}

void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	udp_packet_t* udp_packet = process_packet_from_pcap(user, pkthdr, packet);

	if(!udp_packet) {
		return;
	}

	//collect global
	global_bandwidth_statistics->interval_total_current_bytes_rx += udp_packet->raw_packet_length;
	global_bandwidth_statistics->interval_total_current_packets_rx++;
	global_bandwidth_statistics->grand_total_bytes_rx += udp_packet->raw_packet_length;
	global_bandwidth_statistics->grand_total_packets_rx++;
	atsc3_global_statistics->packets_total_received++;

	//drop mdNS
	if(udp_packet->udp_flow.dst_ip_addr == UDP_FILTER_MDNS_IP_ADDRESS && udp_packet->udp_flow.dst_port == UDP_FILTER_MDNS_PORT) {
		atsc3_global_statistics->packet_counter_filtered_ipv4++;
		//printf("setting dns current_bytes_rx: %d, packets_rx: %d", global_bandwidth_statistics->interval_filtered_current_bytes_rx, global_bandwidth_statistics->interval_filtered_current_packets_rx);
		global_bandwidth_statistics->interval_filtered_current_bytes_rx += udp_packet->data->p_size;
		global_bandwidth_statistics->interval_filtered_current_packets_rx++;

		return udp_packet_free(&udp_packet);
	}

	if(udp_packet->udp_flow.dst_ip_addr == LLS_DST_ADDR && udp_packet->udp_flow.dst_port == LLS_DST_PORT) {
		global_bandwidth_statistics->interval_lls_current_bytes_rx += udp_packet->data->p_size;
		global_bandwidth_statistics->interval_lls_current_packets_rx++;

		atsc3_global_statistics->packet_counter_lls_packets_received++;

		//process as lls.sst, dont free as we keep track of our object in the lls_slt_monitor

		atsc3_lls_table_t* lls_table = lls_table_create_or_update_from_lls_slt_monitor_with_metrics(lls_slt_monitor, udp_packet->data, &atsc3_global_statistics->packet_counter_lls_packets_parsed, &atsc3_global_statistics->packet_counter_lls_packets_parsed_update, &atsc3_global_statistics->packet_counter_lls_packets_parsed_error);
        lls_table = atsc3_lls_table_find_slt_if_signedMultiTable(lls_table);

        if(lls_table) {

			if(lls_table->lls_table_id == SLT) {

				atsc3_global_statistics->packet_counter_lls_slt_packets_parsed++;
				int retval = lls_slt_table_perform_update(lls_table, lls_slt_monitor);

				if(!retval) {
					atsc3_global_statistics->packet_counter_lls_slt_update_processed++;
				} else {
					atsc3_global_statistics->packet_counter_lls_slt_packets_parsed_error++;
				}
			}
		}

		return udp_packet_free(&udp_packet);
	}


	//ATSC3/331 Section 6.1 - drop non mulitcast ip ranges - e.g not in  239.255.0.0 to 239.255.255.255
//    if(udp_packet->udp_flow.dst_ip_addr <= MIN_ATSC3_MULTICAST_BLOCK || udp_packet->udp_flow.dst_ip_addr >= MAX_ATSC3_MULTICAST_BLOCK) {
//        //out of range, so drop
//        count_packet_as_filtered(udp_packet);
//
//        //goto cleanup;
//        return udp_packet_free(udp_packet);
//    }
//    
    if((dst_ip_addr_filter && udp_packet->udp_flow.dst_ip_addr != *dst_ip_addr_filter)) {
        count_packet_as_filtered(udp_packet);
        return udp_packet_free(&udp_packet);
    }

	//ALC (ROUTE) - If this flow is registered from the SLT, process it as ALC, otherwise run the flow thru MMT
	lls_sls_alc_session_t* matching_lls_slt_alc_session = lls_slt_alc_session_find_from_udp_packet(lls_slt_monitor, udp_packet->udp_flow.src_ip_addr, udp_packet->udp_flow.dst_ip_addr, udp_packet->udp_flow.dst_port);
	if(matching_lls_slt_alc_session) {
		global_bandwidth_statistics->interval_alc_current_bytes_rx += udp_packet->data->p_size;
		global_bandwidth_statistics->interval_alc_current_packets_rx++;
		atsc3_global_statistics->packet_counter_alc_recv++;

        atsc3_alc_packet_t* alc_packet = route_parse_from_udp_packet(matching_lls_slt_alc_session, udp_packet);
        if(alc_packet) {
            route_process_from_alc_packet(&udp_packet->udp_flow, &alc_packet);
            alc_packet_free(&alc_packet);
        }
        
        return udp_packet_free(&udp_packet);
	}

	//find our matching MMT flow and push it to reconsitution
    lls_sls_mmt_session_t* matching_lls_sls_mmt_session = lls_sls_mmt_session_find_from_udp_packet(lls_slt_monitor, udp_packet->udp_flow.src_ip_addr, udp_packet->udp_flow.dst_ip_addr, udp_packet->udp_flow.dst_port);
    if(matching_lls_sls_mmt_session) {
        __TRACE("data len: %d", udp_packet->data_length);
        update_global_mmtp_statistics_from_udp_packet_t(matching_lls_sls_mmt_session, udp_packet);

        return udp_packet_free(&udp_packet);
	}

    //if we get here, we don't know what type of packet it is..
    atsc3_global_statistics->packet_counter_udp_unknown++;
    return udp_packet_free(&udp_packet);
}


void* pcap_loop_run_thread(void* dev_pointer) {
	char* dev = (char*) dev_pointer;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	pcap_lookupnet(dev, &netp, &maskp, errbuf);
    descr = pcap_open_live(dev, MAX_PCAP_LEN, 1, 1, errbuf);

    if(descr == NULL) {
        printf("pcap_open_live(): %s",errbuf);
        exit(1);
    }

    //alp0 (and other ALP-decapsulating netdevs) hand up bare IP with no L2 header (DLT_RAW);
    //process_packet_from_pcap() defaults to assuming DLT_EN10MB (Ethernet), so tell it otherwise
    //(port of the same fix already applied to atsc3_listener_metrics_ncurses.cpp)
    int datalink = pcap_datalink(descr);
    if (datalink == DLT_RAW) {
        atsc3_listener_udp_set_l2_header_len(0);
    } else if (datalink != DLT_EN10MB) {
        fprintf(stderr, "pcap_loop_run_thread: unsupported pcap datalink type: %d, expected DLT_EN10MB or DLT_RAW\n", datalink);
        exit(1);
    }

    char filter[] = "udp";
    if(pcap_compile(descr,&fp, filter,0,netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile");
        exit(1);
    }

    if(pcap_setfilter(descr,&fp) == -1) {
        fprintf(stderr,"Error setting filter");
        exit(1);
    }

    pcap_loop(descr,-1,process_packet,NULL);

    return 0;
}


/**
 *
 * atsc3_mmt_listener_test interface (dst_ip) (dst_port)
 *
 * arguments:
 */
int main(int argc,char **argv) {
    _MMT_MPU_PARSER_DEBUG_ENABLED = 0;
    _MMTP_DEBUG_ENABLED = 0;
    _MMT_SIGNALLING_MESSAGE_DEBUG_ENABLED = 0;
    
    _AEAT_PARSER_DEBUG_ENABLED = 1;
    _AEAT_PARSER_TRACE_ENABLED = 1;
    
    _LLS_INFO_ENABLED = 1;


#ifdef __LOTS_OF_DEBUGGING__
	_MMT_MPU_PARSER_DEBUG_ENABLED = 0;
	_MMTP_DEBUG_ENABLED = 0;
	_MMT_SIGNALLING_MESSAGE_TRACE_ENABLED = 0;

	_MMT_RECON_FROM_SAMPLE_DEBUG_ENABLED = 1;
	_MMT_RECON_FROM_SAMPLE_TRACE_ENABLED = 1;

	_LLS_DEBUG_ENABLED = 0;
    _PLAYER_FFPLAY_DEBUG_ENABLED = 1;
    _PLAYER_FFPLAY_TRACE_ENABLED = 0;

    _XML_INFO_ENABLED = 1;
   	_XML_DEBUG_ENABLED = 0;
   	_XML_TRACE_ENABLED = 0;

    _ALC_UTILS_IOTRACE_ENABLED = 1;
    _ALC_UTILS_DEBUG_ENABLED = 1;
    _ALC_UTILS_TRACE_ENABLED = 1;
    _ALC_RX_DEBUG_ENABLED = 1;
    _ALC_RX_TRACE_ENABLED = 1;

    _LLS_SLS_MONITOR_OUTPUT_BUFFER_UTILS_DEBUG_ENABLED = 1;
    _FDT_PARSER_DEBUG_ENABLED=1;

    
    //recon debugging
    _LLS_SLS_MONITOR_OUTPUT_BUFFER_UTILS_TRACE_ENABLED = 1;
    _LLS_SLS_MONITOR_OUTPUT_BUFFER_UTILS_DEBUG_ENABLED = 1;

#endif

    char *dev;

    char *filter_dst_ip = NULL;
    char *filter_dst_port = NULL;
    char *filter_packet_id = NULL;

    int dst_port_filter_int;
    int dst_ip_port_filter_int;
    int dst_packet_id_filter_int;

    sigset_t player_signal_mask;

    //listen to all flows
    if(argc == 2) {
    	dev = argv[1];
    	__INFO("listening on dev: %s", dev);
    } else if(argc>=4) {
    	//listen to a selected flow
    	dev = argv[1];
    	filter_dst_ip = argv[2];

		//skip ip address filter if our params are * or -
    	if(!(strncmp("*", filter_dst_ip, 1) == 0 || strncmp("-", filter_dst_ip, 1) == 0)) {
			dst_ip_addr_filter = (uint32_t*)calloc(1, sizeof(uint32_t));
			char* pch = strtok (filter_dst_ip,".");
			int offset = 24;
			while (pch != NULL && offset>=0) {
				uint8_t octet = atoi(pch);
				*dst_ip_addr_filter |= octet << offset;
				offset-=8;
				pch = strtok (NULL, ".");
			}
		}

    	if(argc>=4) {
    		filter_dst_port = argv[3];
        	if(!(strncmp("*", filter_dst_port, 1) == 0 || strncmp("-", filter_dst_port, 1) == 0)) {

				dst_port_filter_int = atoi(filter_dst_port);
				dst_ip_port_filter = (uint16_t*)calloc(1, sizeof(uint16_t));
				*dst_ip_port_filter |= dst_port_filter_int & 0xFFFF;
        	}
    	}

    	if(argc>=5) {
    		filter_packet_id = argv[4];
        	if(!(strncmp("*", filter_packet_id, 1) == 0 || strncmp("-", filter_packet_id, 1) == 0)) {
				dst_packet_id_filter_int = atoi(filter_packet_id);
				dst_packet_id_filter = (uint16_t*)calloc(1, sizeof(uint16_t));
				*dst_packet_id_filter |= dst_packet_id_filter_int & 0xFFFF;
        	}
    	}

    	__INFO("listening on dev: %s, dst_ip: %s (%p), dst_port: %s (%p), dst_packet_id: %s (%p)", dev, filter_dst_ip, dst_ip_addr_filter, filter_dst_port, dst_ip_port_filter, filter_packet_id, dst_packet_id_filter);


    } else {
    	println("%s - a udp mulitcast listener test harness for atsc3 mmt messages", argv[0]);
    	println("---");
    	println("args: dev (dst_ip) (dst_port) (packet_id)");
    	println(" dev: device to listen for udp multicast, default listen to 0.0.0.0:0");
    	println(" (dst_ip): optional, filter to specific ip address");
    	println(" (dst_port): optional, filter to specific port");
    	println(" (packet_id): optional, filter to specific packet_id across all streams");

    	println("");
    	exit(1);
    }
    // mkdir("mpu", 0777);
    // mkdir("route", 0777);
    
    /** setup global structs **/
    lls_slt_monitor = lls_slt_monitor_create();
    mmtp_flow = mmtp_flow_new();
    udp_flow_latest_mpu_sequence_number_container = udp_flow_latest_mpu_sequence_number_container_t_init();

    gettimeofday(&atsc3_global_statistics->program_timeval_start, 0);

    global_bandwidth_statistics = (bandwidth_statistics_t*)calloc(1, sizeof(*global_bandwidth_statistics));
	gettimeofday(&global_bandwidth_statistics->program_timeval_start, NULL);


    //create our background thread for bandwidth calculation
    /** ncurses support - valgrind on osx will fail in pthread_create...**/

#ifndef _TEST_RUN_VALGRIND_OSX_

	//block sigpipe before creating our threads
	sigemptyset (&player_signal_mask);
	sigaddset (&player_signal_mask, SIGPIPE);
	int rc = pthread_sigmask (SIG_BLOCK, &player_signal_mask, NULL);
	if(!rc) {
		  __WARN("Unable to block SIGPIPE, this may result in a runtime crash when closing ffplay!");
	}

	pthread_t global_ncurses_input_thread_id;
	int ncurses_input_ret = pthread_create(&global_ncurses_input_thread_id, NULL, ncurses_input_run_thread, (void*)lls_slt_monitor);
	assert(!ncurses_input_ret);

	pthread_t global_bandwidth_thread_id;
	pthread_create(&global_bandwidth_thread_id, NULL, print_bandwidth_statistics_thread, NULL);

	pthread_t global_stats_thread_id;
	pthread_create(&global_stats_thread_id, NULL, print_global_statistics_thread, NULL);

	pthread_t global_slt_thread_id;
	pthread_create(&global_slt_thread_id, NULL, print_lls_instance_table_thread, (void*)lls_slt_monitor);

	pthread_t global_http_thread_id;
	pthread_create(&global_http_thread_id, NULL, global_httpd_run_thread, (void*)lls_slt_monitor);

	pthread_t global_pcap_thread_id;
	int pcap_ret = pthread_create(&global_pcap_thread_id, NULL, pcap_loop_run_thread, (void*)dev);
	assert(!pcap_ret);

	//jjustman's original code gated this behind __LIBATSC3_AUTOPLAY__, which is
	//never defined anywhere in the build (no -D flag in the makefile) - so this
	//thread, and the ROUTE/ALC fallback added to it above, never actually ran.
	pthread_t global_autoplay_thread_id;
	pthread_create(&global_autoplay_thread_id, NULL, global_autoplay_run_thread, NULL);

	pthread_t global_route_file_watcher_thread_id;
	pthread_create(&global_route_file_watcher_thread_id, NULL, route_file_watcher_run_thread, NULL);

	pthread_join(global_pcap_thread_id, NULL);
	pthread_join(global_ncurses_input_thread_id, NULL);

#else
	pcap_loop_run_thread(dev);
#endif

    return 0;
}

