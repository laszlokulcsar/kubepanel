# dashboard/views_logging.py

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from datetime import datetime, timedelta
from dashboard.models import LogEntry, Domain
from dashboard.services.logging_service import LogQueryManager
import json

@login_required
def system_logs(request):
    """
    Main system logs view - shows all logs the user has permission to see
    """
    # Get filter parameters
    level_filter = request.GET.get('level', '')
    search_query = request.GET.get('search', '')
    days_filter = request.GET.get('days', '7')
    
    try:
        days = int(days_filter)
    except ValueError:
        days = 7
    
    # Start with base query based on user permissions
    logs_queryset = LogQueryManager.get_user_logs(request.user, limit=1000)
    
    # Apply filters
    if level_filter:
        logs_queryset = logs_queryset.filter(level=level_filter)
    
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(message__icontains=search_query) |
            Q(actor__icontains=search_query)
        )
    
    # Filter by date range
    if days > 0:
        cutoff_date = datetime.now() - timedelta(days=days)
        logs_queryset = logs_queryset.filter(timestamp__gte=cutoff_date)
    
    # Pagination
    paginator = Paginator(logs_queryset, 50)  # Show 50 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get available levels for filter dropdown
    available_levels = LogEntry.LEVEL_CHOICES
    
    context = {
        'page_obj': page_obj,
        'available_levels': available_levels,
        'current_level': level_filter,
        'current_search': search_query,
        'current_days': days,
        'total_logs': logs_queryset.count(),
    }
    
    return render(request, 'logging/system_logs.html', context)

@login_required
def log_detail(request, log_id):
    """
    Detailed view of a single log entry
    """
    log_entry = get_object_or_404(LogEntry, id=log_id)
    
    # Check permissions
    if not request.user.is_superuser and log_entry.user != request.user:
        # Additional permission check based on content object
        if hasattr(log_entry.content_object, 'owner'):
            if log_entry.content_object.owner != request.user:
                return render(request, 'main/error.html', {
                    'error': 'You do not have permission to view this log entry.'
                })
        else:
            return render(request, 'main/error.html', {
                'error': 'You do not have permission to view this log entry.'
            })
    
    # Format JSON data for display
    formatted_data = None
    if log_entry.data:
        try:
            formatted_data = json.dumps(log_entry.data, indent=2)
        except:
            formatted_data = str(log_entry.data)
    
    context = {
        'log_entry': log_entry,
        'formatted_data': formatted_data,
    }
    
    return render(request, 'logging/log_detail.html', context)

@login_required
def object_logs(request, content_type_id, object_id):
    """
    View logs for a specific object (e.g., domain, mail user, etc.)
    """
    content_type = get_object_or_404(ContentType, id=content_type_id)
    
    try:
        content_object = content_type.get_object_for_this_type(pk=object_id)
    except content_type.model_class().DoesNotExist:
        return render(request, 'main/error.html', {
            'error': 'Object not found.'
        })
    
    # Get logs for this object
    logs_queryset = LogQueryManager.get_object_logs(content_object, request.user)
    
    # Apply any additional filters
    level_filter = request.GET.get('level', '')
    if level_filter:
        logs_queryset = logs_queryset.filter(level=level_filter)
    
    # Pagination
    paginator = Paginator(logs_queryset, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'content_object': content_object,
        'page_obj': page_obj,
        'available_levels': LogEntry.LEVEL_CHOICES,
        'current_level': level_filter,
        'content_type_name': content_type.model,
    }
    
    return render(request, 'logging/object_logs.html', context)

@login_required
def error_logs(request):
    """
    Show only error and critical logs
    """
    logs_queryset = LogQueryManager.get_recent_errors(request.user, limit=200)
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(message__icontains=search_query) |
            Q(actor__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(logs_queryset, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'current_search': search_query,
        'total_errors': logs_queryset.count(),
    }
    
    return render(request, 'logging/error_logs.html', context)

@login_required
def logs_api(request):
    """
    JSON API endpoint for logs (for AJAX requests, charts, etc.)
    """
    # Get parameters
    limit = min(int(request.GET.get('limit', 100)), 500)  # Max 500
    level = request.GET.get('level', '')
    hours = int(request.GET.get('hours', 24))
    
    # Get logs
    logs_queryset = LogQueryManager.get_user_logs(request.user, limit)
    
    # Apply filters
    if level:
        logs_queryset = logs_queryset.filter(level=level)
    
    if hours > 0:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        logs_queryset = logs_queryset.filter(timestamp__gte=cutoff_time)
    
    # Convert to JSON-serializable format
    logs_data = []
    for log in logs_queryset:
        logs_data.append({
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'level': log.level,
            'actor': log.actor,
            'message': log.message,
            'content_type': str(log.content_type),
            'object_id': log.object_id,
            'data': log.data,
        })
    
    return JsonResponse({
        'logs': logs_data,
        'count': len(logs_data),
        'total_available': logs_queryset.count()
    })

@login_required
def logs_stats(request):
    """
    Show logging statistics and charts
    """
    user_logs = LogQueryManager.get_user_logs(request.user, limit=10000)
    
    # Calculate statistics
    stats = {
        'total_logs': user_logs.count(),
        'last_24h': user_logs.filter(
            timestamp__gte=datetime.now() - timedelta(days=1)
        ).count(),
        'last_week': user_logs.filter(
            timestamp__gte=datetime.now() - timedelta(days=7)
        ).count(),
    }
    
    # Count by level
    level_stats = {}
    for level, _ in LogEntry.LEVEL_CHOICES:
        level_stats[level] = user_logs.filter(level=level).count()
    
    # Recent activity (last 7 days, grouped by day)
    recent_activity = []
    for i in range(7):
        date = datetime.now().date() - timedelta(days=i)
        count = user_logs.filter(
            timestamp__date=date
        ).count()
        recent_activity.append({
            'date': date.isoformat(),
            'count': count
        })
    
    recent_activity.reverse()  # Oldest first for charts
    
    context = {
        'stats': stats,
        'level_stats': level_stats,
        'recent_activity': recent_activity,
    }
    
    return render(request, 'logging/logs_stats.html', context)
